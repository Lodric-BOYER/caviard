"""Readers for exported traces and logs.

Supported inputs, optionally gzip-compressed (``.gz``):

- OTLP JSON, as written by the OpenTelemetry Collector file exporter: one
  ``ExportTraceServiceRequest`` or ``ExportLogsServiceRequest`` per line, or a
  single document;
- JSON Lines or a JSON array of objects, such as structured logs or a
  Langfuse export: each object is a record and its top-level keys are fields;
- plain text: each line is a record.

Readers only extract values; they never print or log them.
"""

from __future__ import annotations

import gzip
import json
import zlib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from caviard.core.errors import CaviardError

__all__ = ["FORMATS", "Field", "FileStats", "Record", "read"]

FORMATS = ("auto", "otlp", "jsonl", "text")
_MEGABYTE = 1024 * 1024
# Memory bounds: a JSON document is read and parsed at once (several times its size in
# memory), lines are read one at a time. Longer lines are skipped, counted, never held.
_MAX_DOCUMENT = 64 * _MEGABYTE  # characters of a single JSON document
_MAX_LINE = 16 * _MEGABYTE  # characters of one line of JSON Lines or text
_SPAN_SCOPES = ("scopeSpans", "instrumentationLibrarySpans")  # current and legacy names
_LOG_SCOPES = ("scopeLogs", "instrumentationLibraryLogs")


@dataclass(frozen=True)
class Field:
    """One value to analyse and where it was found.

    ``attribute`` is true when ``key`` is a real attribute or field name, the
    kind of key a policy key rule can target.
    """

    source: str  # span, event, link, status, resource, log, record, text
    key: str
    value: Any
    detail: str = ""  # event name
    attribute: bool = True


@dataclass
class Record:
    """A span, a log record, a JSON object or a text line."""

    kind: str  # span, log, record, text, resource
    service: str = ""
    scope: str = ""
    fields: list[Field] = field(default_factory=list)


@dataclass
class FileStats:
    name: str
    format: str = ""
    records: int = 0
    unreadable: int = 0  # lines that were not valid JSON in a JSON file
    ignored: int = 0  # JSON values that are not OTLP requests, with the otlp format
    invalid_json: bool = False  # looked like one JSON document, was read as text
    too_long: int = 0  # lines longer than the line size cap: skipped, not analysed


def read(path: Path, fmt: str = "auto", stats: FileStats | None = None) -> Iterator[Record]:
    """Yield the records of one file."""
    if fmt not in FORMATS:
        raise CaviardError(f"unknown format {fmt!r}: expected one of {', '.join(FORMATS)}")
    stats = stats if stats is not None else FileStats(path.name)
    try:
        with _open(path) as handle:
            yield from _read(handle, fmt, stats)
    except (OSError, EOFError, zlib.error):
        raise CaviardError(f"cannot read {stats.name!r}") from None


def _open(path: Path) -> IO[str]:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace")


def _read(handle: IO[str], fmt: str, stats: FileStats) -> Iterator[Record]:
    if fmt == "text":
        stats.format = "text"
        yield from _counted(_text_records(handle, stats), stats)
        return
    first = _first_line(handle)
    if not first:
        stats.format = fmt if fmt != "auto" else "empty"
        return
    if len(first) > _MAX_DOCUMENT:  # no line end within the document size cap
        if fmt != "auto" or first.lstrip()[:1] in ("{", "["):
            raise _too_large(stats)
        stats.format = "text"
        handle.seek(0)
        yield from _counted(_text_records(handle, stats), stats)
        return
    try:
        parsed: Any = json.loads(first)
    except (ValueError, RecursionError):
        parsed = None
    if isinstance(parsed, dict | list):
        stats.format = "jsonl"
        yield from _counted(_json_lines(parsed, handle, fmt, stats), stats)
        _check_otlp(fmt, stats)
        return
    if first.lstrip()[:1] in ("{", "["):
        document = _document(first, handle, stats)
        if document is not None:
            stats.format = "json"
            yield from _counted(_objects(document, fmt, stats), stats)
            _check_otlp(fmt, stats)
            return
        if fmt != "auto":
            raise CaviardError(f"{stats.name!r} is not valid JSON")
        stats.invalid_json = True
    elif fmt != "auto":
        raise CaviardError(f"{stats.name!r} is not a JSON file (use --format text)")
    stats.format = "text"
    handle.seek(0)
    yield from _counted(_text_records(handle, stats), stats)


def _check_otlp(fmt: str, stats: FileStats) -> None:
    # Read as OTLP on request, a file of other JSON values would look clean.
    if fmt == "otlp" and stats.format != "otlp" and stats.ignored:
        raise CaviardError(f"{stats.name!r} holds no OTLP request (use --format jsonl)")


def _counted(records: Iterable[Record], stats: FileStats) -> Iterator[Record]:
    for record in records:
        if record.kind != "resource":
            stats.records += 1
        yield record


def _first_line(handle: IO[str]) -> str:
    """The first line that is not blank, read up to the document size cap (minified JSON)."""
    while True:
        line = handle.readline(_MAX_DOCUMENT + 1)
        if not line or line.strip():
            return line


def _lines(handle: IO[str], stats: FileStats) -> Iterator[str]:
    """The next lines; one longer than the line size cap is skipped piece by piece."""
    while line := handle.readline(_MAX_LINE + 1):
        if len(line) <= _MAX_LINE or line.endswith("\n"):
            yield line
            continue
        stats.too_long += 1
        while (rest := handle.readline(_MAX_LINE)) and not rest.endswith("\n"):
            pass


def _document(first: str, handle: IO[str], stats: FileStats) -> Any:
    rest = handle.read(_MAX_DOCUMENT - len(first))
    if handle.read(1):
        raise _too_large(stats)
    try:
        return json.loads(first + rest)
    except (ValueError, RecursionError):
        return None


def _too_large(stats: FileStats) -> CaviardError:
    if _MAX_DOCUMENT >= _MEGABYTE:
        limit = f"{_MAX_DOCUMENT // _MEGABYTE} MB"
    else:
        limit = f"{_MAX_DOCUMENT} characters"
    return CaviardError(
        f"{stats.name!r} holds a JSON document too large to read at once (over {limit}): "
        "export it as JSON Lines instead"
    )


def _json_lines(parsed: Any, handle: IO[str], fmt: str, stats: FileStats) -> Iterator[Record]:
    yield from _objects(parsed, fmt, stats)
    for line in _lines(handle, stats):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (ValueError, RecursionError):
            stats.unreadable += 1
            yield _text(line)  # still analysed: it may hold personal data
            continue
        yield from _objects(value, fmt, stats)


def _objects(value: Any, fmt: str, stats: FileStats) -> Iterator[Record]:
    """Records of one parsed JSON value: an OTLP request, an object or a list of them."""
    if isinstance(value, list):
        for item in value:
            yield from _objects(item, fmt, stats)
        return
    if isinstance(value, Mapping) and ("resourceSpans" in value or "resourceLogs" in value):
        stats.format = "otlp"
        yield from _otlp(value)
        return
    if fmt == "otlp":
        stats.ignored += 1
        return
    if isinstance(value, Mapping):
        yield _generic(value)
    elif value is not None:
        yield Record("text", fields=[Field("text", "value", value, attribute=False)])


def _generic(value: Mapping[str, Any]) -> Record:
    service = value.get("service.name", value.get("service", ""))
    fields = [Field("record", str(key), item) for key, item in value.items()]
    return Record("record", service=service if isinstance(service, str) else "", fields=fields)


def _text_records(handle: IO[str], stats: FileStats) -> Iterator[Record]:
    for line in _lines(handle, stats):
        if line.strip():
            yield _text(line)


def _text(line: str) -> Record:
    return Record("text", fields=[Field("text", "line", line.rstrip("\r\n"), attribute=False)])


# OTLP JSON (protobuf JSON mapping)


def _otlp(request: Mapping[str, Any]) -> Iterator[Record]:
    for group in _list(request.get("resourceSpans")):
        service, resource = _resource(group)
        if resource.fields:
            yield resource
        for scope_name, span in _scoped(group, _SPAN_SCOPES, "spans"):
            yield Record("span", service, scope_name, _span_fields(span))
    for group in _list(request.get("resourceLogs")):
        service, resource = _resource(group)
        if resource.fields:
            yield resource
        for scope_name, log in _scoped(group, _LOG_SCOPES, "logRecords"):
            fields = [Field("log", "body", _value(log.get("body")), attribute=False)]
            event_name = log.get("eventName")
            if isinstance(event_name, str) and event_name:
                fields.append(Field("log", "event.name", event_name, attribute=False))
            fields += [Field("log", key, value) for key, value in _attributes(log)]
            yield Record("log", service, scope_name, fields)


def _resource(group: Mapping[str, Any]) -> tuple[str, Record]:
    attributes = list(_attributes(_mapping(group.get("resource"))))
    service = next((v for k, v in attributes if k == "service.name" and isinstance(v, str)), "")
    fields = [Field("resource", key, value) for key, value in attributes]
    return service, Record("resource", service, fields=fields)


def _scoped(
    group: Mapping[str, Any], scope_keys: tuple[str, ...], items_key: str
) -> Iterator[tuple[str, Mapping[str, Any]]]:
    for key in scope_keys:
        for scoped in _list(group.get(key)):
            scope = _mapping(scoped.get("scope") or scoped.get("instrumentationLibrary"))
            name = scope.get("name", "")
            for item in _list(scoped.get(items_key)):
                yield (name if isinstance(name, str) else ""), item


def _span_fields(span: Mapping[str, Any]) -> list[Field]:
    fields = [Field("span", "span.name", span.get("name", ""), attribute=False)]
    fields += [Field("span", key, value) for key, value in _attributes(span)]
    for event in _list(span.get("events")):
        name = event.get("name", "")
        detail = name if isinstance(name, str) else ""
        if detail:  # names can hold personal data too ("lookup jean@...")
            fields.append(Field("event", "event.name", detail, attribute=False))
        fields += [Field("event", key, value, detail) for key, value in _attributes(event)]
    for link in _list(span.get("links")):
        fields += [Field("link", key, value) for key, value in _attributes(link)]
    message = _mapping(span.get("status")).get("message")
    if message:
        fields.append(Field("status", "status.message", message, attribute=False))
    return fields


def _attributes(owner: Mapping[str, Any]) -> Iterator[tuple[str, Any]]:
    for item in _list(owner.get("attributes")):
        key = item.get("key")
        if isinstance(key, str):
            yield key, _value(item.get("value"))


def _value(value: Any) -> Any:
    """Python value of an OTLP ``AnyValue``; binary values become ``bytes``."""
    if not isinstance(value, Mapping):
        return value  # tolerate exporters that write plain JSON values
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "intValue" in value:
        try:
            return int(value["intValue"])  # int64 values are JSON strings
        except (TypeError, ValueError):
            return str(value["intValue"])
    if "doubleValue" in value:
        return value["doubleValue"]
    if "arrayValue" in value:
        return [_value(item) for item in _list(_mapping(value["arrayValue"]).get("values"))]
    if "kvlistValue" in value:
        items = _list(_mapping(value["kvlistValue"]).get("values"))
        return {str(item.get("key", "")): _value(item.get("value")) for item in items}
    if "bytesValue" in value:
        return str(value["bytesValue"]).encode()
    return None


def _list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}
