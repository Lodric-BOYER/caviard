"""``caviard bench``: valid synthetic identifiers, full recall, untouched clean texts."""

from __future__ import annotations

import pytest

from caviard.bench import Synthetic, render_bench, run_bench
from caviard.core.checksums import card_ok, iban_ok, nir_ok, siret_ok


def test_synthetic_identifiers_have_valid_check_digits() -> None:
    data = Synthetic(seed=7)
    for _ in range(200):
        assert nir_ok(data.nir())
        assert iban_ok(data.iban())
        assert card_ok(data.card().replace(" ", ""))
        assert siret_ok(data.siret())


def test_bench_measures_recall_and_false_positives() -> None:
    result = run_bench(count=40, seed=11)

    names = [row["name"] for row in result["scenarios"]]
    assert names == [
        "message with identifiers",
        "clean message",
        "tool output (8 kB)",
        "span attributes",
    ]
    for row in result["scenarios"]:
        assert row["mean_us"] > 0
        assert row["p99_us"] >= row["p50_us"]
        if row["recall"] is None:
            assert row["changed_clean_inputs"] == 0
        else:
            assert row["recall"] == 1.0
    text = render_bench(result)
    assert "message with identifiers" in text
    assert "0 changed" in text


def test_bench_needs_inputs() -> None:
    with pytest.raises(ValueError, match="count"):
        run_bench(count=0)
