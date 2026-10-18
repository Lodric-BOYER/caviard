"""OpenTelemetry integration: an exporter wrapper that redacts every span it exports.

Wrap the real exporter, then register the wrapper with a ``BatchSpanProcessor``
so redaction runs on the export thread, off the request path::

    exporter = RedactingSpanExporter(OTLPSpanExporter(), Policy.load("caviard.toml"))
    provider.add_span_processor(BatchSpanProcessor(exporter))

Spans are immutable once ended: the wrapper exports redacted copies (name,
attributes, events, links, status description and resource attributes) and
never modifies the original. If a span cannot be redacted it is quarantined
(only allowed attributes keep their value) or dropped, never exported in clear.
"""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

try:
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import Event, ReadableSpan
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    from opentelemetry.trace import Link, Status
    from opentelemetry.util.types import Attributes
except ImportError as exc:  # pragma: no cover - depends on the environment
    raise ImportError(
        "caviard.otel needs the OpenTelemetry SDK: pip install 'caviard[otel]'"
    ) from exc

from caviard.core.policy import OnError, Policy
from caviard.core.pseudonym import SecretKey
from caviard.core.redactor import Redactor

__all__ = ["QUARANTINED", "QUARANTINE_FLAG", "RedactingSpanExporter"]

QUARANTINED = "[QUARANTINED]"
QUARANTINE_FLAG = "caviard.quarantined"
_RESOURCE_CACHE = 64


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
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()
        self._resources: dict[int, tuple[Resource, Resource]] = {}

    @property
    def counters(self) -> dict[str, int]:
        """Spans redacted, quarantined and dropped since creation."""
        with self._lock:
            return dict(self._counts)

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        safe: list[ReadableSpan] = []
        counts: Counter[str] = Counter()
        for span in spans:
            try:
                safe.append(self._redact(span))
                counts["redacted"] += 1
            except Exception:
                if self.redactor.policy.on_error is OnError.DROP:
                    counts["dropped"] += 1
                    continue
                try:
                    safe.append(self._quarantine(span))
                    counts["quarantined"] += 1
                except Exception:
                    counts["dropped"] += 1
        with self._lock:
            self._counts.update(counts)
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
            Event(event.name, _attributes(redactor, event.attributes), event.timestamp)
            for event in span.events
        ]
        links = [Link(link.context, _attributes(redactor, link.attributes)) for link in span.links]
        status = span.status
        if status.description:
            status = Status(status.status_code, redactor.redact_text(status.description))
        return _copy(
            span,
            name=redactor.redact_text(span.name),
            attributes=_attributes(redactor, span.attributes),
            events=events,
            links=links,
            status=status,
            resource=self._resource(span.resource),
        )

    def _resource(self, resource: Resource) -> Resource:
        """Redacted copy of a resource, cached so that its spans still share one."""
        cached = self._resources.get(id(resource))
        if cached is not None and cached[0] is resource:
            return cached[1]
        redacted = Resource(_attributes(self.redactor, resource.attributes), resource.schema_url)
        if len(self._resources) >= _RESOURCE_CACHE:
            self._resources.clear()
        self._resources[id(resource)] = (resource, redacted)
        return redacted

    def _quarantine(self, span: ReadableSpan) -> ReadableSpan:
        attributes = self._allowed_only(span.attributes)
        attributes[QUARANTINE_FLAG] = True
        return _copy(
            span,
            name=QUARANTINED,
            attributes=attributes,
            events=[],
            links=[Link(link.context) for link in span.links],
            status=Status(span.status.status_code),
            resource=Resource(self._allowed_only(span.resource.attributes)),
        )

    def _allowed_only(self, attributes: Attributes) -> dict[str, Any]:
        policy = self.redactor.policy
        return {
            key: value if policy.key_decision(key) == "allow" else QUARANTINED
            for key, value in (attributes or {}).items()
        }


def _attributes(redactor: Redactor, attributes: Attributes) -> dict[str, Any]:
    return redactor.redact_attributes(attributes)


def _copy(
    span: ReadableSpan,
    *,
    name: str,
    attributes: Mapping[str, Any],
    events: list[Event],
    links: list[Link],
    status: Status,
    resource: Resource,
) -> ReadableSpan:
    return ReadableSpan(
        name=name,
        context=span.context,
        parent=span.parent,
        resource=resource,
        attributes=attributes,
        events=events,
        links=links,
        kind=span.kind,
        status=status,
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )
