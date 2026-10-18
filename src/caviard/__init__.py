"""Caviard: fail-closed redaction of personal data in AI agent traces and logs.

Quick start::

    import caviard

    caviard.redact("Mon numéro de sécu est 1 85 03 75 112 345 94")
    # -> 'Mon numéro de sécu est [FR_NIR]'
"""

from __future__ import annotations

import threading

from caviard.core import (
    Action,
    CaviardError,
    CaviardWarning,
    Detector,
    EntityRule,
    Finding,
    OnError,
    Policy,
    PolicyError,
    RedactionError,
    RedactionStats,
    Redactor,
    SecretKey,
    generate_key,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "Action",
    "CaviardError",
    "CaviardWarning",
    "Detector",
    "EntityRule",
    "Finding",
    "OnError",
    "Policy",
    "PolicyError",
    "RedactionError",
    "RedactionStats",
    "Redactor",
    "SecretKey",
    "__version__",
    "generate_key",
    "redact",
    "scan",
]

_default: Redactor | None = None
_default_lock = threading.Lock()


def _default_redactor() -> Redactor:
    global _default
    if _default is None:
        with _default_lock:
            if _default is None:
                _default = Redactor()
    return _default


def redact(text: str, policy: Policy | None = None) -> str:
    """Redact a text with ``policy`` (default: the "standard" preset)."""
    redactor = _default_redactor() if policy is None else Redactor(policy)
    return redactor.redact_text(text)


def scan(text: str, policy: Policy | None = None) -> list[Finding]:
    """Return what would be redacted in ``text``: entity types and spans, never values."""
    redactor = _default_redactor() if policy is None else Redactor(policy)
    return redactor.findings(text)
