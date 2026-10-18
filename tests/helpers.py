"""Shared test helpers (importable thanks to ``pythonpath = ["tests"]``)."""

from __future__ import annotations

import json
import re
import string
from collections.abc import Iterable
from typing import Any

from caviard import Detector, Policy, Redactor
from caviard.core.checksums import luhn_ok

TEST_KEY = "a" * 64  # hex-encoded 32-byte key, for tests only


def make_redactor(policy: Policy | None = None, **changes: Any) -> Redactor:
    """A Redactor without plugins and with a fixed pseudonym key."""
    base = policy if policy is not None else Policy.default()
    return Redactor(base.replace(plugins=False, **changes), pseudonym_key=TEST_KEY)


def luhn_complete(prefix: str) -> str:
    """Append the Luhn check digit to a string of digits."""
    for digit in string.digits:
        if luhn_ok(prefix + digit):
            return prefix + digit
    raise AssertionError("unreachable")


def nir_with_key(body: str) -> str:
    """Complete a 13-character NIR body with its key (handles Corsica 2A/2B)."""
    department = body[5:7]
    numeric = body[:5] + {"2A": "19", "2B": "18"}.get(department, department) + body[7:]
    return f"{body}{97 - int(numeric) % 97:02d}"


def spaced_nir(nir: str) -> str:
    return f"{nir[0]} {nir[1:3]} {nir[3:5]} {nir[5:7]} {nir[7:10]} {nir[10:13]} {nir[13:]}"


def _explode(value: str) -> bool:
    raise RuntimeError("detector failure")


def exploding_redactor(policy: Policy | None = None, **changes: Any) -> Redactor:
    """A Redactor whose extra detector fails on every word, to exercise quarantine paths."""
    base = policy if policy is not None else Policy.default()
    explode = Detector("explode", "BOOM", re.compile(r"\w+"), validate=_explode)
    return Redactor(
        base.replace(plugins=False, **changes), extra_detectors=[explode], pseudonym_key=TEST_KEY
    )


def _fallback(value: Any) -> Any:
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return dump()
        except Exception:
            return repr(value)
    return repr(value)


def dump(value: Any) -> str:
    """Serialise anything (objects included) to search it for raw values."""
    return json.dumps(value, default=_fallback, ensure_ascii=False)


def leaked(text: str | bytes, values: Iterable[str]) -> list[str]:
    """The raw values found in ``text``; an empty list means nothing leaked."""
    if isinstance(text, bytes):
        return [value for value in values if value.encode() in text]
    return [value for value in values if value in text]
