"""Detection quality on synthetic French traces: no leak, no false positive."""

from __future__ import annotations

from collections import Counter

import pytest

from helpers import make_redactor
from synthetic import Generator

POSITIVES = 1500
NEGATIVES = 1500


def _forms(value: str) -> set[str]:
    return {value, "".join(value.split())}


def test_synthetic_traces(capsys: pytest.CaptureFixture[str]) -> None:
    generator = Generator(seed=20261018)
    redactor = make_redactor()
    total: Counter[str] = Counter()
    leaked: Counter[str] = Counter()
    for _ in range(POSITIVES):
        sample = generator.positive()
        output = redactor.redact_value(sample.text)
        for entity, value in sample.values:
            total[entity] += 1
            if any(form in output for form in _forms(value)):
                leaked[entity] += 1
    false_positives = 0
    for _ in range(NEGATIVES):
        text = generator.negative()
        if redactor.findings(text) or redactor.redact_value(text) != text:
            false_positives += 1

    with capsys.disabled():
        print("\n  entity        values  leaked  recall")
        for entity in sorted(total):
            recall = 1 - leaked[entity] / total[entity]
            print(f"  {entity:<12} {total[entity]:>7} {leaked[entity]:>7}  {recall:6.1%}")
        print(f"  negatives {NEGATIVES}, false positives {false_positives}")
    assert not leaked, f"leaked entity types: {dict(leaked)}"
    assert false_positives == 0
