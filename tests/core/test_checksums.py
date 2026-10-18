from __future__ import annotations

import random

import pytest
from faker import Faker

from caviard.core.checksums import card_ok, iban_ok, luhn_ok, nir_ok, rpps_ok, siren_ok, siret_ok
from helpers import nir_with_key, spaced_nir

ROUNDS = 1000


def test_faker_identifiers_are_valid(fake: Faker) -> None:
    for _ in range(ROUNDS):
        assert nir_ok(fake.ssn())
        assert siren_ok(fake.siren())
        assert siret_ok(fake.siret())
        assert iban_ok(fake.iban())
        assert card_ok(fake.credit_card_number())


@pytest.mark.parametrize(
    "locale",
    ["de_DE", "es_ES", "it_IT", "nl_NL", "en_GB", "pl_PL", "pt_PT", "fi_FI", "de_AT", "fr_CH"],
)
def test_european_ibans_are_valid(locale: str) -> None:
    faker = Faker(locale)
    faker.seed_instance(7)
    for _ in range(200):
        assert iban_ok(faker.iban())


def test_single_digit_substitutions_are_rejected(fake: Faker) -> None:
    rng = random.Random(1)
    cases = [
        (fake.ssn, nir_ok),
        (lambda: fake.siren().replace(" ", ""), siren_ok),
        (lambda: fake.siret().replace(" ", ""), siret_ok),
        (fake.iban, iban_ok),
        (fake.credit_card_number, card_ok),
    ]
    for generate, validate in cases:
        for _ in range(300):
            value = generate()
            index = rng.choice([i for i, char in enumerate(value) if char.isdigit()])
            changed = str((int(value[index]) + rng.randint(1, 9)) % 10)
            assert not validate(value[:index] + changed + value[index + 1 :])


def test_nir_with_separators_and_corsica() -> None:
    for department in ("75", "2A", "2B"):
        nir = nir_with_key("185" + "03" + department + "112" + "345")
        assert nir_ok(nir)
        assert nir_ok(spaced_nir(nir))
        assert nir_ok(nir.replace("A", "a").replace("B", "b"))
        wrong_key = f"{(int(nir[-2:]) + 1) % 100:02d}"
        assert not nir_ok(nir[:-2] + wrong_key)


@pytest.mark.parametrize("first_digit", ["0", "5", "6", "9"])
def test_nir_rejects_unused_first_digits(first_digit: str) -> None:
    assert not nir_ok(nir_with_key(first_digit + "850375112345"))


def test_la_poste_siret_uses_digit_sum() -> None:
    candidates = [f"356000000{nic:05d}" for nic in range(1000)]
    valid = next(c for c in candidates if sum(map(int, c)) % 5 == 0)
    assert siret_ok(valid)
    invalid = next(c for c in candidates if sum(map(int, c)) % 5 and luhn_ok(c))
    assert not siret_ok(invalid)


def test_rpps_published_example() -> None:
    assert rpps_ok("10000812437")  # example published by the French health agency (ANS)
    assert not rpps_ok("10000812438")
    assert not rpps_ok("1000081243")


def test_iban_rules() -> None:
    assert iban_ok("FR76 3000 6000 0112 3456 7890 189")
    assert iban_ok("fr7630006000011234567890189")
    assert not iban_ok("FR763000600001123456789018")  # wrong length for France
    assert not iban_ok("FR7630006000011234567890188")  # wrong check digits
    assert not iban_ok("7630006000011234567890189FR")
    assert not iban_ok("FR76-3000-6000-0112-3456-7890-189")


def test_only_ascii_digits_are_accepted() -> None:
    arabic_indic = "".join(chr(0x0660 + int(char)) for char in "732829320")
    fullwidth = "".join(chr(0xFF10 + int(char)) for char in "732829320")
    for value in (arabic_indic, fullwidth):
        assert not luhn_ok(value)
        assert not siren_ok(value)
    assert not luhn_ok("")
    assert not luhn_ok("12a4")


def test_random_numbers_explain_context_rules() -> None:
    """Luhn alone accepts about 1 random number in 10, the NIR key about 1 in 100."""
    rng = random.Random(42)

    def digits(count: int) -> str:
        return "".join(rng.choice("0123456789") for _ in range(count))

    luhn_rate = sum(siren_ok(digits(9)) for _ in range(20_000)) / 20_000
    nir_rate = sum(nir_ok(rng.choice("12") + digits(14)) for _ in range(20_000)) / 20_000
    assert 0.08 < luhn_rate < 0.12
    assert nir_rate < 0.02
