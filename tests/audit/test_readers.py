"""Readers: OTLP JSON (lines or document), JSON Lines, JSON arrays, text, gzip."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

import otlp
from caviard import CaviardError
from caviard.audit import readers
from caviard.audit.readers import FileStats, Record, read


def _records(path: Path, fmt: str = "auto") -> tuple[list[Record], FileStats]:
    stats = FileStats(path.name)
    return list(read(path, fmt, stats)), stats


def _keys(record: Record) -> list[tuple[str, str]]:
    return [(field.source, field.key) for field in record.fields]


def test_otlp_traces_as_json_lines(tmp_path: Path) -> None:
    request = otlp.traces(
        [
            otlp.span(
                "chat",
                {"gen_ai.prompt": "bonjour", "gen_ai.usage.input_tokens": 12},
                events=[("exception", {"exception.message": "boom"})],
                links=[{"handoff.note": "suite"}],
                status="failed",
            )
        ],
        resource={"service.name": "support-agent", "host.name": "worker-1"},
        scope="openinference.instrumentation.openai",
    )
    path = otlp.write_jsonl(tmp_path / "traces.jsonl", [request, request])

    records, stats = _records(path)

    assert stats.format == "otlp"
    assert stats.records == 2  # resources are not records
    assert [record.kind for record in records] == ["resource", "span", "resource", "span"]
    resource, span = records[0], records[1]
    assert _keys(resource) == [("resource", "service.name"), ("resource", "host.name")]
    assert span.service == "support-agent"
    assert span.scope == "openinference.instrumentation.openai"
    assert _keys(span) == [
        ("span", "span.name"),
        ("span", "gen_ai.prompt"),
        ("span", "gen_ai.usage.input_tokens"),
        ("event", "exception.message"),
        ("link", "handoff.note"),
        ("status", "status.message"),
    ]
    assert span.fields[2].value == 12  # int64 decoded from its JSON string
    assert span.fields[3].detail == "exception"
    assert not span.fields[0].attribute  # span names cannot be targeted by key rules


def test_otlp_logs_and_legacy_names(tmp_path: Path) -> None:
    legacy = {
        "resourceSpans": [
            {
                "resource": {"attributes": []},
                "instrumentationLibrarySpans": [
                    {"instrumentationLibrary": {"name": "old"}, "spans": [otlp.span("legacy")]}
                ],
            }
        ]
    }
    request = otlp.logs(
        [("Connexion de l'utilisateur", {"user.role": "admin"})], resource={"service.name": "api"}
    )
    path = otlp.write_jsonl(tmp_path / "mixed.jsonl", [legacy, request])

    records, _ = _records(path)

    kinds = [record.kind for record in records]
    assert kinds == ["span", "resource", "log"]
    assert records[0].scope == "old"
    assert records[2].service == "api"
    assert _keys(records[2]) == [("log", "body"), ("log", "user.role")]


def test_otlp_value_types() -> None:
    assert readers._value({"stringValue": "a"}) == "a"
    assert readers._value({"boolValue": True}) is True
    assert readers._value({"intValue": "123456789012"}) == 123456789012
    assert readers._value({"intValue": "not a number"}) == "not a number"
    assert readers._value({"doubleValue": 0.5}) == 0.5
    assert readers._value(otlp.value(["a", 1])) == ["a", 1]
    assert readers._value(otlp.value({"k": {"n": 2}})) == {"k": {"n": 2}}
    assert isinstance(readers._value(otlp.value(b"\x00\x01")), bytes)
    assert readers._value({}) is None
    assert readers._value("plain") == "plain"  # exporters that write plain JSON values
    owner = {"attributes": [{"key": 1, "value": {}}, "junk", {"key": "ok", "value": "v"}]}
    assert list(readers._attributes(owner)) == [("ok", "v")]


def test_single_json_document(tmp_path: Path) -> None:
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(otlp.traces([otlp.span("a"), otlp.span("b")]), indent=2))

    records, stats = _records(path)

    assert stats.format == "otlp"
    assert [record.kind for record in records] == ["span", "span"]


def test_json_lines_of_objects_with_a_broken_line(tmp_path: Path) -> None:
    path = tmp_path / "app.jsonl"
    path.write_text(
        '{"event": "login", "user_email": "x", "service": "api"}\n'
        "\n"
        "not json at all\n"
        '[{"event": "a"}, {"event": "b"}]\n',
        encoding="utf-8",
    )

    records, stats = _records(path)

    assert stats.format == "jsonl"
    assert stats.unreadable == 1
    assert [record.kind for record in records] == ["record", "text", "record", "record"]
    assert records[0].service == "api"
    assert _keys(records[0]) == [
        ("record", "event"),
        ("record", "user_email"),
        ("record", "service"),
    ]
    assert records[1].fields[0].value == "not json at all"


def test_json_array_of_scalars_and_objects(tmp_path: Path) -> None:
    path = tmp_path / "export.json"
    path.write_text('[\n  "texte libre",\n  {"input": "q"},\n  null\n]\n', encoding="utf-8")

    records, stats = _records(path)

    assert stats.format == "json"
    assert [record.kind for record in records] == ["text", "record"]


def test_text_and_gzip(tmp_path: Path) -> None:
    text = tmp_path / "app.log"
    text.write_text("première ligne\n\n{pas du json\n", encoding="utf-8")
    compressed = tmp_path / "app.log.gz"
    with gzip.open(compressed, "wt", encoding="utf-8") as handle:
        handle.write(text.read_text(encoding="utf-8"))

    for path in (text, compressed):
        records, stats = _records(path)
        assert stats.format == "text"
        assert [record.fields[0].value for record in records] == ["première ligne", "{pas du json"]


def test_forced_formats(tmp_path: Path) -> None:
    lines = otlp.write_jsonl(
        tmp_path / "lines.jsonl", [{"event": "a"}, otlp.traces([otlp.span("s")])]
    )
    records, stats = _records(lines, "otlp")
    assert [record.kind for record in records] == ["span"]
    assert stats.unreadable == 1

    records, stats = _records(lines, "text")
    assert stats.format == "text"
    assert len(records) == 2

    text = tmp_path / "app.log"
    text.write_text("hello\n", encoding="utf-8")
    with pytest.raises(CaviardError, match="not a JSON file"):
        _records(text, "jsonl")
    broken = tmp_path / "broken.json"
    broken.write_text("{\n  oops\n", encoding="utf-8")
    with pytest.raises(CaviardError, match="not valid JSON"):
        _records(broken, "otlp")
    assert _records(broken)[1].format == "text"  # auto falls back to text


def test_empty_and_unreadable_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n\n", encoding="utf-8")
    assert _records(empty) == ([], FileStats("empty.jsonl", format="empty"))

    with pytest.raises(CaviardError, match=r"cannot read 'absent\.jsonl'"):
        _records(tmp_path / "absent.jsonl")
    corrupted = tmp_path / "corrupted.gz"
    corrupted.write_bytes(b"\x1f\x8b\x08\x00garbage")
    with pytest.raises(CaviardError, match="cannot read"):
        _records(corrupted)
    with pytest.raises(CaviardError, match="unknown format"):
        _records(empty, "xml")

    big = tmp_path / "big.json"
    big.write_text("{\n" + '"a": 1,\n' * 50 + '"b": 2\n}\n', encoding="utf-8")
    monkeypatch.setattr(readers, "_MAX_DOCUMENT", 20)
    with pytest.raises(CaviardError, match="too large"):
        _records(big)
