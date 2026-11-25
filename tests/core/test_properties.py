"""Property-based tests: invariants that must hold for any input."""

from __future__ import annotations

import itertools
import json
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from helpers import make_redactor
from synthetic import Generator

REDACTOR = make_redactor()


def _snippets() -> list[tuple[str, list[str]]]:
    generator = Generator(seed=7)
    snippets: list[tuple[str, list[str]]] = []
    while len(snippets) < 60:
        sample = generator.positive()
        if not sample.text.startswith("["):  # plain-text samples only
            snippets.append((sample.text, [value for _, value in sample.values]))
    return snippets


SNIPPETS = _snippets()
SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=40),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=10), children, max_size=4)
    ),
    max_leaves=20,
)


@SETTINGS
@given(st.text(max_size=300))
def test_any_text_is_stable(text: str) -> None:
    once = REDACTOR.redact_text(text)
    assert REDACTOR.redact_text(once) == once
    assert REDACTOR.findings(once) == []


@SETTINGS
@given(st.lists(st.one_of(st.text(max_size=30), st.integers(0, len(SNIPPETS) - 1)), max_size=8))
def test_known_values_never_survive(parts: list[Any]) -> None:
    pieces: list[str] = []
    values: list[str] = []
    for part in parts:
        if isinstance(part, int):
            text, secrets = SNIPPETS[part]
            pieces.append(text)
            values.extend(secrets)
        else:
            pieces.append(part)
    output = REDACTOR.redact_text(" \n ".join(pieces))
    for value in values:
        assert value not in output


@SETTINGS
@given(json_values)
def test_json_documents_stay_valid_and_stable(document: Any) -> None:
    text = json.dumps([document], ensure_ascii=False)
    once = REDACTOR.redact_value(text)
    json.loads(once)
    assert REDACTOR.redact_value(once) == once


python_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False)
    | st.text(max_size=20)
    | st.binary(max_size=8),
    lambda children: (
        st.lists(children, max_size=3)
        | st.tuples(children, children)
        | st.frozensets(st.text(max_size=8), max_size=3)
        | st.dictionaries(st.text(max_size=8) | st.integers(), children, max_size=3)
    ),
    max_leaves=15,
)


@SETTINGS
@given(python_values, st.lists(st.integers(0, len(SNIPPETS) - 1), min_size=1, max_size=3))
def test_identifiers_in_keys_and_values_never_survive(base: Any, picks: list[int]) -> None:
    texts = [SNIPPETS[index] for index in picks]
    secrets = [value for _, values in texts for value in values]
    first, last = texts[0][0], texts[-1][0]
    document = {"payload": base, first: [base, last], "seen": (first, {last: base})}
    once = REDACTOR.redact_value(document)
    rendered = repr(once)
    assert [secret for secret in secrets if secret in rendered] == []
    assert REDACTOR.redact_value(once) == once


# Characters that the patterns see through: zero-width space, no-break space, fullwidth
# digits and "@", en dash, a combining accent, the soft hyphen.
DISGUISES = [chr(0x200B), chr(0xA0), chr(0xFF10), chr(0xFF16), chr(0xFF20), chr(0x2013)]
DISGUISES += [chr(0x301), chr(0xAD)]
disguised_text = st.text(
    alphabet=st.sampled_from([*"abcdej@.:= 0612'\"[]{}(),", *DISGUISES]), max_size=120
)


@SETTINGS
@given(disguised_text)
def test_findings_on_disguised_texts_are_valid_spans(text: str) -> None:
    found = REDACTOR.findings(text)
    for finding in found:
        assert 0 <= finding.start < finding.end <= len(text)
    for before, after in itertools.pairwise(found):
        assert before.end <= after.start
    once = REDACTOR.redact_text(text)
    assert REDACTOR.redact_text(once) == once


@SETTINGS
@given(
    st.lists(st.sampled_from(DISGUISES), max_size=4),
    st.lists(st.integers(0, 21), max_size=4),
)
def test_disguised_addresses_never_survive(marks: list[str], places: list[int]) -> None:
    address = list("jean.dupont@exemple.fr")
    for mark, place in zip(marks, places, strict=False):
        if mark in (chr(0x200B), chr(0xAD)):  # invisible: inserted anywhere
            address.insert(min(place, len(address)), mark)
    text = "écrire à " + "".join(address) + ", merci"
    output = REDACTOR.redact_text(text)
    assert "dupont" not in output
    assert "exemple" not in output
