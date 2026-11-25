"""Bounded time on hostile inputs (invariant I4)."""

from __future__ import annotations

import json
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
    # Dense with real findings: each one costs a validation and a pseudonym.
    "url credentials": "://a:" * (MEGABYTE // 5),
    "ipv6 words": "a::b " * (MEGABYTE // 5),
    "emails": "a@b.cd " * (MEGABYTE // 7),
    "phones": "06 12 34 56 78 " * (MEGABYTE // 15),
    "field values": "nom='x' " * (MEGABYTE // 8),
    # Escaped characters, read by the second email pattern.
    "escape runs": "\\x41" * (MEGABYTE // 4) + "@",
    "escaped addresses": ("\\x41" * 64 + "@" + ("\\x41" * 20 + ".") * 8 + " ") * 1_100,
    "logfmt": "a=b " * (MEGABYTE // 4),
    # Objects looked for inside texts.
    "python dicts": "{'a': " * (MEGABYTE // 6),
    "dict reprs": "{'nom': 'x'} " * (MEGABYTE // 13),
    "templates": "{x} " * (MEGABYTE // 4),
    # Values after field names, read whole.
    "colon values": "nom: x " * (MEGABYTE // 7),
    "bracket values": "address=[" * (MEGABYTE // 9),
    "spaced values": "password=a" + " " * (MEGABYTE - 10),
    "glued placeholders": "password=[SECRET]" * (MEGABYTE // 17),
    "nested pairs": "url=a?token=" * (MEGABYTE // 12),
    # Characters normalised before detection.
    "zero-width": ("a" + chr(0x200B)) * (MEGABYTE // 2),
    "fullwidth digits": chr(0xFF10) * MEGABYTE,
    "combining accents": ("e" + chr(0x301)) * (MEGABYTE // 2),
    "objects": "{'a': 1} " * (MEGABYTE // 9),
}


@pytest.mark.parametrize("method", ["redact_text", "redact_value"])
@pytest.mark.parametrize("name", list(PAYLOADS))
def test_hostile_text_is_bounded(name: str, method: str) -> None:
    redactor = make_redactor(max_chars=2 * MEGABYTE)
    start = time.perf_counter()
    getattr(redactor, method)(PAYLOADS[name])
    assert time.perf_counter() - start < LIMIT_SECONDS


def test_too_many_matches_replace_the_value() -> None:
    redactor = make_redactor(max_chars=2 * MEGABYTE)
    assert redactor.redact_text(PAYLOADS["emails"]) == "[REDACTED]"
    some = "jean@exemple.fr " * 100
    assert redactor.redact_text(some).count("[EMAIL:") == 100


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


def test_clean_structured_texts_are_kept_and_fast() -> None:
    redactor = make_redactor(max_chars=2 * MEGABYTE)
    # More field names than the 10,000-match budget: names alone never spend it.
    logfmt = " ".join(f"k{index}=v{index}" for index in range(15_000))
    assert redactor.redact_value(logfmt) == logfmt
    # Half a megabyte of distinct keys, each one checked.
    document = json.dumps({f"k{index}": index for index in range(30_000)})
    start = time.perf_counter()
    assert redactor.redact_value(document) == document
    assert time.perf_counter() - start < LIMIT_SECONDS
