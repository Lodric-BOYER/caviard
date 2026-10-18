from __future__ import annotations

import pytest

import caviard
from caviard import Policy


@pytest.mark.filterwarnings("ignore::caviard.CaviardWarning")
def test_docstring_example() -> None:
    assert caviard.redact("Mon numéro de sécu est 1 85 03 75 112 345 94") == (
        "Mon numéro de sécu est [FR_NIR]"
    )


def test_scan_with_policy() -> None:
    findings = caviard.scan("écrire à jean@exemple.fr", Policy.from_preset("strict"))
    assert [(f.entity, f.start, f.end) for f in findings] == [("EMAIL", 9, 24)]


def test_public_names() -> None:
    for name in caviard.__all__:
        assert hasattr(caviard, name)
