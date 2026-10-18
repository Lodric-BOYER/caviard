"""Hand-written OTLP JSON documents (protobuf JSON mapping), as the Collector writes them."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

TRACE_ID = "5b8efff798038103d269b633813fc60c"
SPAN_ID = "eee19b7ec3c1b174"


def value(item: Any) -> dict[str, Any]:
    if isinstance(item, bool):
        return {"boolValue": item}
    if isinstance(item, int):
        return {"intValue": str(item)}  # int64 values are JSON strings
    if isinstance(item, float):
        return {"doubleValue": item}
    if isinstance(item, bytes):
        return {"bytesValue": base64.b64encode(item).decode()}
    if isinstance(item, list):
        return {"arrayValue": {"values": [value(entry) for entry in item]}}
    if isinstance(item, Mapping):
        return {"kvlistValue": {"values": attributes(item)}}
    return {"stringValue": str(item)}


def attributes(mapping: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [{"key": key, "value": value(item)} for key, item in mapping.items()]


def span(
    name: str,
    attrs: Mapping[str, Any] | None = None,
    *,
    events: Iterable[tuple[str, Mapping[str, Any]]] = (),
    links: Iterable[Mapping[str, Any]] = (),
    status: str | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "traceId": TRACE_ID,
        "spanId": SPAN_ID,
        "name": name,
        "kind": 1,
        "attributes": attributes(attrs or {}),
    }
    if events:
        document["events"] = [
            {"name": event, "attributes": attributes(items)} for event, items in events
        ]
    if links:
        document["links"] = [
            {"traceId": TRACE_ID, "spanId": SPAN_ID, "attributes": attributes(items)}
            for items in links
        ]
    if status is not None:
        document["status"] = {"code": 2, "message": status}
    return document


def traces(
    spans: Iterable[dict[str, Any]],
    resource: Mapping[str, Any] | None = None,
    scope: str = "tests",
) -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": attributes(resource or {})},
                "scopeSpans": [{"scope": {"name": scope}, "spans": list(spans)}],
            }
        ]
    }


def logs(
    records: Iterable[tuple[Any, Mapping[str, Any]]],
    resource: Mapping[str, Any] | None = None,
    scope: str = "tests",
) -> dict[str, Any]:
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": attributes(resource or {})},
                "scopeLogs": [
                    {
                        "scope": {"name": scope},
                        "logRecords": [
                            {
                                "severityText": "INFO",
                                "body": value(body),
                                "attributes": attributes(items),
                            }
                            for body, items in records
                        ],
                    }
                ],
            }
        ]
    }


def write_jsonl(path: Path, documents: Iterable[Any]) -> Path:
    path.write_text("".join(json.dumps(doc) + "\n" for doc in documents), encoding="utf-8")
    return path
