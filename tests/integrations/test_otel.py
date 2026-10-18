"""OpenTelemetry exporter wrapper: what goes on the wire is redacted, originals stay intact."""

from __future__ import annotations

import json

import pytest
from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExportResult,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Link, SpanContext, Status, StatusCode, TraceFlags

from caviard import OnError, Policy
from caviard.otel import QUARANTINE_FLAG, QUARANTINED, RedactingSpanExporter
from helpers import TEST_KEY, exploding_redactor, leaked, make_redactor

_REMOTE = SpanContext(
    trace_id=0x5B8EFFF798038103D269B633813FC60C,
    span_id=0x051581BF3CB55C13,
    is_remote=True,
    trace_flags=TraceFlags(TraceFlags.SAMPLED),
)


def _pipeline(
    exporter: RedactingSpanExporter, resource: Resource | None = None
) -> tuple[TracerProvider, InMemorySpanExporter]:
    """A provider exporting through ``exporter`` and, in parallel, to a raw exporter."""
    provider = TracerProvider(resource=resource) if resource else TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    raw = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(raw))
    return provider, raw


def _agent_span(provider: TracerProvider, pii: dict[str, str]) -> None:
    tracer = provider.get_tracer("tests")
    links = [Link(_REMOTE, {"handoff.note": f"transféré par {pii['email']}"})]
    with tracer.start_as_current_span(f"lookup {pii['email']}", links=links) as span:
        span.set_attribute("gen_ai.request.model", "gpt-4o-mini")
        span.set_attribute("gen_ai.usage.input_tokens", 42)
        span.set_attribute("gen_ai.prompt", f"Client {pii['email']}, tél. {pii['phone']}")
        span.set_attribute("user.email", pii["email"])
        span.set_attribute("enduser.id", "customer-1042")
        span.set_attribute(
            "gen_ai.tool.call.arguments",
            json.dumps({"iban": pii["iban"], "note": f"NIR {pii['nir']}"}),
        )
        span.set_attribute("app.tags", ["vip", pii["email"]])
        span.add_event("retry", {"reason": f"key {pii['api_key']} rejected"})
        try:
            raise ValueError(f"no account for {pii['email']}")
        except ValueError as exc:
            span.record_exception(exc)
        span.set_status(Status(StatusCode.ERROR, f"failed for {pii['phone']}"))


def test_exported_spans_are_redacted_on_the_wire(pii: dict[str, str]) -> None:
    inner = InMemorySpanExporter()
    exporter = RedactingSpanExporter(inner, redactor=make_redactor())
    provider, raw = _pipeline(exporter)
    _agent_span(provider, pii)

    (span,) = inner.get_finished_spans()
    wire = encode_spans([span]).SerializeToString()
    assert leaked(wire, pii.values()) == []
    # Same spans, unredacted, through the parallel processor: the data was there.
    raw_wire = encode_spans(raw.get_finished_spans()).SerializeToString()
    assert sorted(leaked(raw_wire, pii.values())) == sorted(pii.values())

    attributes = span.attributes or {}
    assert attributes["gen_ai.request.model"] == "gpt-4o-mini"
    assert attributes["gen_ai.usage.input_tokens"] == 42
    assert attributes["user.email"] == "[REDACTED]"
    assert str(attributes["enduser.id"]).startswith("[REDACTED:")
    assert json.loads(str(attributes["gen_ai.tool.call.arguments"])) == {
        "iban": "[REDACTED]",
        "note": "NIR [FR_NIR]",
    }
    tags = attributes["app.tags"]
    assert isinstance(tags, tuple)
    assert tags[0] == "vip"
    assert str(tags[1]).startswith("[EMAIL:")
    assert span.name.startswith("lookup [EMAIL:")
    assert span.status.status_code is StatusCode.ERROR
    assert "[FR_PHONE:" in (span.status.description or "")
    assert [event.name for event in span.events] == ["retry", "exception"]
    assert span.links[0].context == _REMOTE
    assert exporter.counters == {"redacted": 1}


def test_original_spans_are_not_modified(pii: dict[str, str]) -> None:
    captured: list[ReadableSpan] = []

    class Capture(InMemorySpanExporter):
        def export(self, spans):
            captured.extend(spans)
            return super().export(spans)

    exporter = RedactingSpanExporter(Capture(), redactor=make_redactor())
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    raw = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(raw))
    _agent_span(provider, pii)

    (original,) = raw.get_finished_spans()
    assert original.attributes is not None
    assert original.attributes["user.email"] == pii["email"]
    assert captured[0] is not original


def _resource(pii: dict[str, str]) -> Resource:
    return Resource.create(
        {
            "service.name": "support-agent",
            "process.command_line": f"python agent.py --api-key {pii['api_key']}",
            "deployment.owner": pii["email"],
        }
    )


def test_resource_attributes_are_redacted_once_per_resource(pii: dict[str, str]) -> None:
    inner = InMemorySpanExporter()
    exporter = RedactingSpanExporter(inner, redactor=make_redactor())
    provider, raw = _pipeline(exporter, _resource(pii))
    tracer = provider.get_tracer("tests")
    for name in ("plan", "act"):
        with tracer.start_as_current_span(name):
            pass

    first, second = inner.get_finished_spans()
    assert first.resource is second.resource  # still one resource group on the wire
    assert first.resource.attributes["service.name"] == "support-agent"
    assert leaked(encode_spans([first, second]).SerializeToString(), pii.values()) == []
    raw_wire = encode_spans(raw.get_finished_spans()).SerializeToString()
    assert pii["api_key"].encode() in raw_wire


def test_quarantine_keeps_only_allowed_attributes(pii: dict[str, str]) -> None:
    inner = InMemorySpanExporter()
    exporter = RedactingSpanExporter(inner, redactor=exploding_redactor())
    provider, _ = _pipeline(exporter, _resource(pii))
    _agent_span(provider, pii)

    (span,) = inner.get_finished_spans()
    assert leaked(encode_spans([span]).SerializeToString(), pii.values()) == []
    attributes = span.attributes or {}
    assert attributes[QUARANTINE_FLAG] is True
    assert attributes["gen_ai.request.model"] == "gpt-4o-mini"
    assert attributes["gen_ai.prompt"] == QUARANTINED
    assert span.name == QUARANTINED
    assert span.events == ()
    assert not span.links[0].attributes
    assert span.status.status_code is StatusCode.ERROR
    assert span.status.description is None
    assert span.resource.attributes["service.name"] == "support-agent"
    assert span.resource.attributes["process.command_line"] == QUARANTINED
    assert exporter.counters == {"quarantined": 1}


def test_on_error_drop_exports_nothing(pii: dict[str, str]) -> None:
    inner = InMemorySpanExporter()
    redactor = exploding_redactor(on_error=OnError.DROP)
    exporter = RedactingSpanExporter(inner, redactor=redactor)
    provider, _ = _pipeline(exporter)
    _agent_span(provider, pii)

    assert inner.get_finished_spans() == ()
    assert exporter.counters == {"dropped": 1}


def test_failed_quarantine_drops_the_span(
    pii: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    inner = InMemorySpanExporter()
    exporter = RedactingSpanExporter(inner, redactor=exploding_redactor())

    def broken(span: ReadableSpan) -> ReadableSpan:
        raise RuntimeError("quarantine failure")

    monkeypatch.setattr(exporter, "_quarantine", broken)
    provider, _ = _pipeline(exporter)
    _agent_span(provider, pii)

    assert inner.get_finished_spans() == ()
    assert exporter.counters == {"dropped": 1}


def test_empty_batch_is_a_success() -> None:
    exporter = RedactingSpanExporter(InMemorySpanExporter(), redactor=make_redactor())
    assert exporter.export([]) is SpanExportResult.SUCCESS
    assert exporter.force_flush() is True


def test_batch_processor_flush_and_shutdown(pii: dict[str, str]) -> None:
    inner = InMemorySpanExporter()
    exporter = RedactingSpanExporter(inner, Policy.default(), pseudonym_key=TEST_KEY)
    provider = TracerProvider()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    tracer = provider.get_tracer("tests")
    for index in range(5):
        with tracer.start_as_current_span(f"step {index}") as span:
            span.set_attribute("gen_ai.prompt", f"écrire à {pii['email']}")

    assert provider.force_flush()
    spans = inner.get_finished_spans()
    assert len(spans) == 5
    assert leaked(encode_spans(spans).SerializeToString(), pii.values()) == []
    # One pseudonym per value: the same email gives the same token in every span.
    assert len({(span.attributes or {})["gen_ai.prompt"] for span in spans}) == 1
    provider.shutdown()
    assert exporter.counters == {"redacted": 5}


def test_resource_cache_is_bounded(pii: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    import caviard.otel

    monkeypatch.setattr(caviard.otel, "_RESOURCE_CACHE", 1)
    inner = InMemorySpanExporter()
    exporter = RedactingSpanExporter(inner, redactor=make_redactor())
    for owner in ("a@exemple.fr", "b@exemple.fr"):
        provider = TracerProvider(resource=Resource.create({"deployment.owner": owner}))
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        with provider.get_tracer("tests").start_as_current_span("step"):
            pass
    first, second = inner.get_finished_spans()
    assert first.resource is not second.resource
    assert (
        leaked(encode_spans([first, second]).SerializeToString(), ["a@exemple.fr", "b@exemple.fr"])
        == []
    )
