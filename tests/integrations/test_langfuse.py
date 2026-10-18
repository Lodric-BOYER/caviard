"""Langfuse ``mask_otel_spans`` hook: unit tests and an end-to-end run of the SDK."""

from __future__ import annotations

import json
import uuid
from types import MappingProxyType
from typing import Any

import pytest
from opentelemetry.exporter.otlp.proto.common.trace_encoder import encode_spans
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from caviard import OnError, Policy
from caviard.integrations.langfuse import QUARANTINE_FLAG, QUARANTINED, mask_otel_spans
from helpers import TEST_KEY, exploding_redactor, leaked, make_redactor

pytestmark = pytest.mark.integration
lf_types = pytest.importorskip("langfuse.types")


def _params(*attribute_sets: dict[str, Any]) -> Any:
    spans = {}
    for index, attributes in enumerate(attribute_sets, start=1):
        identifier = lf_types.OtelSpanIdentifier(trace_id="ab" * 16, span_id=f"{index:016x}")
        spans[identifier] = lf_types.OtelSpanData(
            trace_id=identifier.trace_id,
            span_id=identifier.span_id,
            parent_span_id=None,
            name="generation",
            instrumentation_scope_name="langfuse-sdk",
            instrumentation_scope_version="5",
            attributes=MappingProxyType(attributes),
            resource_attributes=MappingProxyType({}),
        )
    return lf_types.MaskOtelSpansParams(spans=MappingProxyType(spans))


def _patches(result: Any) -> list[Any]:
    assert isinstance(result, lf_types.MaskOtelSpansResult)
    return list(result.span_patches.values())


def _langfuse_attributes(pii: dict[str, str]) -> dict[str, Any]:
    return {
        "langfuse.observation.type": "generation",
        "langfuse.observation.model.name": "gpt-4o-mini",
        "langfuse.observation.input": json.dumps(
            [{"role": "user", "content": f"Mon IBAN est {pii['iban']}, mail {pii['email']}"}]
        ),
        "langfuse.observation.output": json.dumps(f"Je vous rappelle au {pii['phone']}"),
        "langfuse.observation.metadata.email": json.dumps(pii["email"]),
        "user.email": pii["email"],
        "gen_ai.usage.input_tokens": 120,
    }


def test_hook_redacts_and_keeps_langfuse_values_valid_json(pii: dict[str, str]) -> None:
    hook = mask_otel_spans(redactor=make_redactor())
    attributes = _langfuse_attributes(pii)
    (patch,) = _patches(hook(params=_params(attributes)))

    patched = {**attributes, **patch.set_attributes}
    for key in set(patch.delete_attributes):
        patched.pop(key)
    assert leaked(json.dumps(patched), pii.values()) == []
    for key in ("input", "output", "metadata.email"):
        json.loads(patched[f"langfuse.observation.{key}"])  # still valid JSON for Langfuse
    # Unchanged values are not part of the patch.
    assert "langfuse.observation.type" not in patch.set_attributes
    assert "gen_ai.usage.input_tokens" not in patch.set_attributes
    assert patch.set_attributes["user.email"] == "[REDACTED]"
    assert json.loads(patch.set_attributes["langfuse.observation.metadata.email"]) == "[REDACTED]"


def test_clean_span_gets_no_patch() -> None:
    hook = mask_otel_spans(redactor=make_redactor())
    result = hook(params=_params({"langfuse.observation.output": json.dumps("Bonjour !")}))
    assert _patches(result) == []


def test_dropped_keys_are_deleted(pii: dict[str, str]) -> None:
    policy = Policy.default().replace(drop_keys=("http.request.header.cookie",))
    hook = mask_otel_spans(redactor=make_redactor(policy))
    attributes = {"http.request.header.cookie": f"session=1; mail={pii['email']}"}
    (patch,) = _patches(hook(params=_params(attributes)))
    assert tuple(patch.delete_attributes) == ("http.request.header.cookie",)
    assert patch.set_attributes == {}


def test_failing_span_is_quarantined_and_the_batch_survives(pii: dict[str, str]) -> None:
    hook = mask_otel_spans(redactor=exploding_redactor())
    attributes = _langfuse_attributes(pii)
    # The second span only has allowed keys: nothing to redact, nothing fails.
    result = hook(params=_params(attributes, {"langfuse.observation.type": "span"}))
    (patch,) = _patches(result)

    patched = {**attributes, **patch.set_attributes}
    assert leaked(json.dumps(patched), pii.values()) == []
    assert patched[QUARANTINE_FLAG] is True
    assert patched["langfuse.observation.model.name"] == "gpt-4o-mini"  # allowed key
    assert json.loads(patched["langfuse.observation.input"]) == QUARANTINED
    assert patched["user.email"] == QUARANTINED


def test_on_error_drop_deletes_unsafe_keys(pii: dict[str, str]) -> None:
    hook = mask_otel_spans(redactor=exploding_redactor(on_error=OnError.DROP))
    attributes = _langfuse_attributes(pii)
    (patch,) = _patches(hook(params=_params(attributes)))

    assert dict(patch.set_attributes) == {QUARANTINE_FLAG: True}
    kept = set(attributes) - set(patch.delete_attributes)
    assert kept == {
        "langfuse.observation.type",
        "langfuse.observation.model.name",
        "gen_ai.usage.input_tokens",
    }


def test_each_span_is_handled_on_its_own(pii: dict[str, str]) -> None:
    hook = mask_otel_spans(Policy.default(), pseudonym_key=TEST_KEY)
    params = _params(
        {"langfuse.observation.output": json.dumps(pii["email"])},
        {"langfuse.observation.output": json.dumps("rien à masquer")},
        {"user.email": pii["email"]},
    )
    assert len(_patches(hook(params=params))) == 2


def test_end_to_end_with_the_langfuse_sdk(pii: dict[str, str]) -> None:
    langfuse = pytest.importorskip("langfuse")
    memory = InMemorySpanExporter()
    client = langfuse.Langfuse(
        public_key=f"pk-lf-test-{uuid.uuid4().hex}",
        secret_key="sk-lf-test",  # never used: spans go to the in-memory exporter
        base_url="http://127.0.0.1:9",
        span_exporter=memory,
        mask_otel_spans=mask_otel_spans(redactor=make_redactor()),
    )
    try:
        with client.start_as_current_observation(
            name="support-agent",
            as_type="generation",
            model="gpt-4o-mini",
            input=[{"role": "user", "content": f"NIR {pii['nir']}, mail {pii['email']}"}],
            metadata={"customer_email": pii["email"]},
        ) as generation:
            generation.update(output=f"Je vous rappelle au {pii['phone']}")
        client.flush()
    finally:
        client.shutdown()

    spans = memory.get_finished_spans()
    assert spans, "the Langfuse SDK exported nothing"
    assert leaked(encode_spans(spans).SerializeToString(), pii.values()) == []
    attributes = spans[0].attributes or {}
    assert attributes["langfuse.observation.model.name"] == "gpt-4o-mini"
    assert "[FR_NIR]" in str(attributes["langfuse.observation.input"])
