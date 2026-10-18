"""Property-based tests: invariants that must hold for any input."""

from __future__ import annotations

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
