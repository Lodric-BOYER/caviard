"""Bounded time on hostile inputs (invariant I4)."""

from __future__ import annotations

import time

import pytest

from helpers import make_redactor

LIMIT_SECONDS = 2.5
MEGABYTE = 1_000_000

PAYLOADS = {
    "digits": "1" * MEGABYTE,
    "spaced digits": "1 " * (MEGABYTE // 2),
    "email-like": "a" * (MEGABYTE - 1) + "@",
    "dots": "a." * (MEGABYTE // 2),
    "at and dots": "a@" + "a." * (MEGABYTE // 2 - 1),
    "jwt-like": "eyJ" + "a" * (MEGABYTE - 3),
    "private key headers": "-----BEGIN RSA PRIVATE KEY-----" * (MEGABYTE // 31),
    "colons": ":" * MEGABYTE,
    "hex and colons": "a:" * (MEGABYTE // 2),
    "plus33": "+33" * (MEGABYTE // 3),
    "brackets": "[A" * (MEGABYTE // 2),
    "api key prefix": "sk-" + "a" * (MEGABYTE - 3),
    "bearer": "Bearer " + "a" * (MEGABYTE - 7),
    "assignments": "password=" * (MEGABYTE // 9),
    "zeros": "0" * MEGABYTE,
    "ipv4-like": "1.1.1." * (MEGABYTE // 6),
}


@pytest.mark.parametrize("name", list(PAYLOADS))
def test_hostile_text_is_bounded(name: str) -> None:
    redactor = make_redactor(max_chars=2 * MEGABYTE)
    start = time.perf_counter()
    redactor.redact_text(PAYLOADS[name])
    assert time.perf_counter() - start < LIMIT_SECONDS


# Named, not passed directly: pytest puts test ids in an environment variable, which
# Windows limits to 32,767 characters.
JSON_PAYLOADS = {
    "nested arrays": "[" * MEGABYTE,
    "nested objects": '{"a":' * (MEGABYTE // 5),
    "open braces": "{" * MEGABYTE,
}


@pytest.mark.parametrize("name", list(JSON_PAYLOADS))
def test_hostile_json_is_bounded(name: str) -> None:
    redactor = make_redactor(max_chars=2 * MEGABYTE)
    start = time.perf_counter()
    redactor.redact_value(JSON_PAYLOADS[name])
    assert time.perf_counter() - start < LIMIT_SECONDS


def test_default_size_cap_is_instant() -> None:
    redactor = make_redactor()
    start = time.perf_counter()
    assert redactor.redact_value("x" * MEGABYTE) == "[TOO_LARGE]"
    assert time.perf_counter() - start < 0.1
