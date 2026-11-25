"""OpenTelemetry integration: exporter wrappers that redact every span and log record.

Wrap the real exporters, then register the wrappers with batch processors so
redaction runs on the export thread, off the request path::

    exporter = RedactingSpanExporter(OTLPSpanExporter(), Policy.load("caviard.toml"))
    provider.add_span_processor(BatchSpanProcessor(exporter))

    logs = RedactingLogExporter(OTLPLogExporter(), Policy.load("caviard.toml"))
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(logs))

Spans and log records are immutable once emitted: the wrappers export redacted
copies and never modify the originals. Spans: name, attributes, events, links,
status description, trace state, resource and instrumentation scope attributes.
Log records: body, attributes, event name, resource and instrumentation scope
attributes; GenAI instrumentations put prompts and completions there. A record that
cannot be redacted is quarantined (only allowed attributes keep their value) or
dropped, never exported in clear.
"""

from __future__ import annotations

import copy
import re
import threading
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Any

try:
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import Event, ReadableSpan
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    from opentelemetry.sdk.util.instrumentation import InstrumentationScope
    from opentelemetry.trace import Link, SpanContext, Status, TraceState
    from opentelemetry.util.types import Attributes
except ImportError as exc:  # pragma: no cover - depends on the environment
    raise ImportError(
        "caviard.otel needs the OpenTelemetry SDK: pip install 'caviard[otel]'"
    ) from exc

try:
    from opentelemetry.sdk._logs import ReadableLogRecord
    from opentelemetry.sdk._logs.export import LogRecordExporter, LogRecordExportResult
except ImportError:  # pragma: no cover - opentelemetry-sdk older than 1.39
    _LOGS = False
    LogRecordExporter = object  # type: ignore[misc,assignment]
else:
    _LOGS = True

from caviard.core.policy import OnError, Policy
from caviard.core.pseudonym import SecretKey
from caviard.core.redactor import Redactor

__all__ = ["QUARANTINED", "QUARANTINE_FLAG", "RedactingLogExporter", "RedactingSpanExporter"]

QUARANTINED = "[QUARANTINED]"
QUARANTINE_FLAG = "caviard.quarantined"
_SHARED_CACHE = 64  # redacted resources and scopes kept, as many records share them
# A W3C trace state value: printable ASCII but "," and "=", 256 characters at most.
_TRACE_STATE_VALUE = re.compile(
    r"[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,255}[\x21-\x2b\x2d-\x3c\x3e-\x7e]"
)


class RedactingSpanExporter(SpanExporter):
    """Wrap a ``SpanExporter`` so that only redacted copies of spans are exported."""

    def __init__(
        self,
        exporter: SpanExporter,
        policy: Policy | None = None,
        *,
        redactor: Redactor | None = None,
        pseudonym_key: bytes | str | SecretKey | None = None,
    ) -> None:
        self._exporter = exporter
        self.redactor = (
            redactor if redactor is not None else Redactor(policy, pseudonym_key=pseudonym_key)
        )
        self._counts = _Counts()
        self._resources = _Shared(lambda resource: _resource_copy(self.redactor, resource))
        self._scopes = _Shared(lambda scope: _scope_copy(self.redactor, scope))

    @property
    def counters(self) -> dict[str, int]:
        """Spans redacted, quarantined and dropped since creation."""
        return self._counts.snapshot()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        safe = _safe_copies(spans, self._redact, self._quarantine, self.redactor, self._counts)
        if not safe:
            return SpanExportResult.SUCCESS
        return self._exporter.export(safe)

    def shutdown(self) -> None:
        self._exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return self._exporter.force_flush(timeout_millis)

    def _redact(self, span: ReadableSpan) -> ReadableSpan:
        redactor = self.redactor
        events = [
            Event(
                _name(redactor, event.name),
                redactor.redact_attributes(event.attributes),
                event.timestamp,
            )
            for event in span.events
        ]
        links = [
            Link(
                _redacted_state(redactor, link.context), redactor.redact_attributes(link.attributes)
            )
            for link in span.links
        ]
        status = span.status
        if status.description:
            status = Status(status.status_code, redactor.redact_value(status.description))
        return _copy(
            span,
            name=_name(redactor, span.name),
            context=_context(redactor, span.context),
            parent=_context(redactor, span.parent),
            attributes=redactor.redact_attributes(span.attributes),
            events=events,
            links=links,
            status=status,
            resource=self._resources.get(span.resource),
            scope=self._scopes.get(span.instrumentation_scope),
        )

    def _quarantine(self, span: ReadableSpan) -> ReadableSpan:
        policy = self.redactor.policy
        attributes = _allowed_only(policy, span.attributes)
        attributes[QUARANTINE_FLAG] = True
        return _copy(
            span,
            name=QUARANTINED,
            context=_stateless(span.context),
            parent=_stateless(span.parent),
            attributes=attributes,
            events=[],
            links=[Link(_with_state(link.context, TraceState())) for link in span.links],
            status=Status(span.status.status_code),
            resource=Resource(_allowed_only(policy, span.resource.attributes)),
            scope=_allowed_scope(policy, span.instrumentation_scope),
        )


class RedactingLogExporter(LogRecordExporter):
    """Wrap a ``LogRecordExporter`` so that only redacted copies of log records are exported.

    Needs opentelemetry-sdk 1.39 or later (``ReadableLogRecord``).
    """

    def __init__(
        self,
        exporter: LogRecordExporter,
        policy: Policy | None = None,
        *,
        redactor: Redactor | None = None,
        pseudonym_key: bytes | str | SecretKey | None = None,
    ) -> None:
        if not _LOGS:
            raise ImportError("RedactingLogExporter needs opentelemetry-sdk 1.39 or later")
        self._exporter = exporter
        self.redactor = (
            redactor if redactor is not None else Redactor(policy, pseudonym_key=pseudonym_key)
        )
        self._counts = _Counts()
        self._resources = _Shared(lambda resource: _resource_copy(self.redactor, resource))
        self._scopes = _Shared(lambda scope: _scope_copy(self.redactor, scope))

    @property
    def counters(self) -> dict[str, int]:
        """Log records redacted, quarantined and dropped since creation."""
        return self._counts.snapshot()

    def export(self, batch: Sequence[ReadableLogRecord]) -> LogRecordExportResult:
        safe = _safe_copies(batch, self._redact, self._quarantine, self.redactor, self._counts)
        if not safe:
            return LogRecordExportResult.SUCCESS
        return self._exporter.export(safe)

    def shutdown(self) -> None:
        exporter: Any = self._exporter  # the SDK leaves this method untyped
        exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return self._exporter.force_flush(timeout_millis)

    def _redact(self, record: ReadableLogRecord) -> ReadableLogRecord:
        redactor = self.redactor
        source = record.log_record
        log = copy.copy(source)
        log.body = redactor.redact_value(source.body)
        log.attributes = redactor.redact_attributes(source.attributes)
        if source.event_name:
            log.event_name = _name(redactor, source.event_name)
        _forget_exception(log)
        return _copy_log(
            record,
            log,
            self._resources.get(record.resource),
            self._scopes.get(record.instrumentation_scope),
        )

    def _quarantine(self, record: ReadableLogRecord) -> ReadableLogRecord:
        policy = self.redactor.policy
        source = record.log_record
        log = copy.copy(source)
        log.body = None if source.body is None else QUARANTINED
        attributes = _allowed_only(policy, source.attributes)
        attributes[QUARANTINE_FLAG] = True
        log.attributes = attributes
        if source.event_name:
            log.event_name = QUARANTINED
        _forget_exception(log)
        return _copy_log(
            record,
            log,
            Resource(_allowed_only(policy, record.resource.attributes)),
            _allowed_scope(policy, record.instrumentation_scope),
        )


class _Counts:
    """Thread-safe counters of redacted, quarantined and dropped records."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()

    def update(self, counts: Mapping[str, int]) -> None:
        with self._lock:
            self._counts.update(counts)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)


class _Shared:
    """Redacted copies of objects that many records share (resources, scopes), cached
    so that the copies are shared too."""

    def __init__(self, redact: Callable[[Any], Any]) -> None:
        self._redact = redact
        self._cache: dict[int, tuple[Any, Any]] = {}

    def get(self, original: Any) -> Any:
        cached = self._cache.get(id(original))
        if cached is not None and cached[0] is original:
            return cached[1]
        copy_ = self._redact(original)
        if len(self._cache) >= _SHARED_CACHE:
            self._cache.clear()
        self._cache[id(original)] = (original, copy_)
        return copy_


def _name(redactor: Redactor, name: str) -> str:
    """A span, event or log event name, redacted like a value (quoted payloads are read
    field by field)."""
    return str(redactor.redact_value(name))


def _context(redactor: Redactor, context: SpanContext | None) -> SpanContext | None:
    return None if context is None else _redacted_state(redactor, context)


def _redacted_state(redactor: Redactor, context: SpanContext) -> SpanContext:
    """The span context, its trace state values redacted: the ``tracestate`` header of a
    request sets them, so they may hold anything. Values that are no longer valid trace
    state values are left out."""
    if not context.trace_state:
        return context
    entries: list[tuple[str, str]] = []
    changed = False
    for key, value in context.trace_state.items():
        redacted = redactor.redact_text(value)
        if redacted != value:
            changed = True
            if not _TRACE_STATE_VALUE.fullmatch(redacted):
                continue
        entries.append((key, redacted))
    if not changed:
        return context
    return _with_state(context, TraceState(entries))


def _stateless(context: SpanContext | None) -> SpanContext | None:
    """The span context without its trace state, for quarantined spans."""
    if context is None or not context.trace_state:
        return context
    return _with_state(context, TraceState())


def _with_state(context: SpanContext, state: TraceState) -> SpanContext:
    return SpanContext(
        context.trace_id, context.span_id, context.is_remote, context.trace_flags, state
    )


def _resource_copy(redactor: Redactor, resource: Resource) -> Resource:
    return Resource(redactor.redact_attributes(resource.attributes), resource.schema_url)


def _scope_copy(redactor: Redactor, scope: InstrumentationScope | None) -> Any:
    if scope is None or not scope.attributes:
        return scope
    attributes = redactor.redact_attributes(scope.attributes)
    return InstrumentationScope(scope.name, scope.version, scope.schema_url, attributes)


def _allowed_scope(policy: Policy, scope: InstrumentationScope | None) -> Any:
    if scope is None or not scope.attributes:
        return scope
    attributes = _allowed_only(policy, scope.attributes)
    return InstrumentationScope(scope.name, scope.version, scope.schema_url, attributes)


def _safe_copies(
    records: Sequence[Any],
    redact: Any,
    quarantine: Any,
    redactor: Redactor,
    counts: _Counts,
) -> list[Any]:
    """Redacted copies; on error, quarantined copies, or nothing (``on_error = "drop"``)."""
    safe: list[Any] = []
    seen: Counter[str] = Counter()
    for record in records:
        try:
            safe.append(redact(record))
            seen["redacted"] += 1
        except Exception:
            if redactor.policy.on_error is OnError.DROP:
                seen["dropped"] += 1
                continue
            try:
                safe.append(quarantine(record))
                seen["quarantined"] += 1
            except Exception:
                seen["dropped"] += 1
    counts.update(seen)
    return safe


def _allowed_only(policy: Policy, attributes: Attributes) -> dict[str, Any]:
    return {
        key: value if policy.key_decision(key) == "allow" else QUARANTINED
        for key, value in (attributes or {}).items()
    }


def _forget_exception(log: Any) -> None:
    # Its type, message and stack trace are already in the attributes, which are redacted.
    if getattr(log, "exception", None) is not None:
        log.exception = None


def _copy(
    span: ReadableSpan,
    *,
    name: str,
    context: SpanContext | None,
    parent: SpanContext | None,
    attributes: Mapping[str, Any],
    events: list[Event],
    links: list[Link],
    status: Status,
    resource: Resource,
    scope: InstrumentationScope | None,
) -> ReadableSpan:
    return ReadableSpan(
        name=name,
        context=context,
        parent=parent,
        resource=resource,
        attributes=attributes,
        events=events,
        links=links,
        kind=span.kind,
        status=status,
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=scope,
    )


def _copy_log(
    record: ReadableLogRecord, log: Any, resource: Resource, scope: InstrumentationScope | None
) -> ReadableLogRecord:
    return ReadableLogRecord(
        log_record=log,
        resource=resource,
        instrumentation_scope=scope,
        limits=record.limits,
    )
