"""Langfuse integration: a ``mask_otel_spans`` hook for the Langfuse Python SDK (v5)::

    from langfuse import Langfuse
    from caviard import Policy
    from caviard.integrations.langfuse import mask_otel_spans

    langfuse = Langfuse(mask_otel_spans=mask_otel_spans(Policy.load("caviard.toml")))

Langfuse drops a whole export batch when the hook raises, so every span is
handled on its own: a span whose redaction fails is quarantined (only allowed
attributes keep their value) while the rest of the batch is exported. Langfuse
only lets the hook change attributes; span events (exception messages) are
not covered here. Wrap the exporter with ``caviard.otel.RedactingSpanExporter``
(``Langfuse(span_exporter=...)``) to cover them too.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from caviard.core import entities as E
from caviard.core.policy import OnError, Policy
from caviard.core.pseudonym import SecretKey
from caviard.core.redactor import Redactor

__all__ = ["QUARANTINED", "QUARANTINE_FLAG", "mask_otel_spans"]

QUARANTINED = "[QUARANTINED]"
QUARANTINE_FLAG = "caviard.quarantined"
# Langfuse stores these values JSON-encoded: replacements must stay valid JSON.
_JSON_PREFIX = "langfuse."

Patch = tuple[dict[str, Any], tuple[str, ...]]


def mask_otel_spans(
    policy: Policy | None = None,
    *,
    redactor: Redactor | None = None,
    pseudonym_key: bytes | str | SecretKey | None = None,
) -> Callable[..., Any]:
    """Return a function to pass as ``Langfuse(mask_otel_spans=...)``."""
    try:
        from langfuse.types import MaskOtelSpansResult, OtelSpanPatch
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise ImportError(
            "this hook needs the Langfuse SDK v5: pip install 'caviard[langfuse]'"
        ) from exc
    engine = redactor if redactor is not None else Redactor(policy, pseudonym_key=pseudonym_key)

    def hook(*, params: Any) -> Any:
        patches: dict[Any, Any] = {}
        for identifier, span in params.spans.items():
            attributes = dict(span.attributes)
            try:
                patch = _patch(engine, attributes)
            except Exception:
                engine.stats.add(E.QUARANTINED)
                patch = _quarantine(engine, attributes)
            if patch is not None:
                changed, deleted = patch
                patches[identifier] = OtelSpanPatch(
                    set_attributes=changed, delete_attributes=deleted
                )
        return MaskOtelSpansResult(span_patches=patches)

    return hook


def _patch(engine: Redactor, attributes: Mapping[str, Any]) -> Patch | None:
    redacted = engine.redact_attributes(attributes)
    changed = {
        key: _encode(key, value, attributes[key])
        for key, value in redacted.items()
        if value != attributes[key]
    }
    deleted = tuple(key for key in attributes if key not in redacted)
    return (changed, deleted) if changed or deleted else None


def _quarantine(engine: Redactor, attributes: Mapping[str, Any]) -> Patch:
    policy = engine.policy
    unsafe = [key for key in attributes if policy.key_decision(key) != "allow"]
    flag: dict[str, Any] = {QUARANTINE_FLAG: True}
    if policy.on_error is OnError.DROP:
        return flag, tuple(unsafe)
    changed = {key: _encode(key, QUARANTINED, attributes[key]) for key in unsafe}
    return {**changed, **flag}, ()


def _encode(key: str, new: Any, old: Any) -> Any:
    if not (key.startswith(_JSON_PREFIX) and isinstance(new, str) and isinstance(old, str)):
        return new
    if not _is_json(old) or _is_json(new):
        return new
    return json.dumps(new, ensure_ascii=False)


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
    except ValueError:
        return False
    return True
