from __future__ import annotations

import json
import re
import warnings
from pathlib import Path

import pytest
from faker import Faker

from caviard import CaviardWarning, Detector, Policy, PolicyError, Redactor
from caviard.core import entities as E
from helpers import TEST_KEY, make_redactor, nir_with_key

TOKEN = re.compile(r"\[([A-Z_]+):([a-z2-7]{12})\]")
NIR = nir_with_key("2690549588157")


def test_actions() -> None:
    text = "IBAN FR76 3000 6000 0112 3456 7890 189 et mail jean@exemple.fr"
    masked = make_redactor(Policy.from_preset("strict")).redact_text(text)
    assert masked == "IBAN [IBAN] et mail [EMAIL]"
    partial = make_redactor(
        Policy.from_dict({"entities": {"IBAN": {"action": "partial", "keep_last": 4}}})
    ).redact_text(text)
    assert partial.startswith("IBAN [IBAN:...0189] et mail [EMAIL:")
    assert TOKEN.search(partial)


def test_pseudonyms_are_stable_keyed_and_format_independent() -> None:
    first, second = make_redactor(), make_redactor()
    other = Redactor(Policy.default().replace(plugins=False), pseudonym_key="b" * 64)
    reference = first.redact_text("tél 06 12 34 56 78")
    assert reference == second.redact_text("tél +33 6 12 34 56 78")
    assert reference == second.redact_text("tél 0033 (0)6 12 34 56 78")
    assert reference != other.redact_text("tél 06 12 34 56 78")
    assert first.redact_text("JEAN@EXEMPLE.FR") == first.redact_text("jean@exemple.fr")


def test_idempotence(redactor: Redactor, fake: Faker) -> None:
    samples = [
        f"sécu {NIR}, mail {fake.email()}, tél {fake.phone_number()}",
        f"SIRET {fake.siret()} et IBAN {fake.iban()}",
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
        json.dumps({"customer_name": fake.name(), "email": fake.email(), "note": "rien"}),
    ]
    for sample in samples:
        once = redactor.redact_value(sample)
        assert once != sample
        assert redactor.redact_value(once) == once


def test_json_tool_arguments(redactor: Redactor, fake: Faker) -> None:
    name, siret = fake.name(), fake.siret().replace(" ", "")
    arguments = {"customer_name": name, "siret": siret, "amount": 120}
    messages = [
        {"role": "user", "content": "Crée la facture"},
        {
            "role": "assistant",
            "tool_calls": [
                {"function": {"name": "creer_facture", "arguments": json.dumps(arguments)}}
            ],
        },
    ]
    output = redactor.redact_value(json.dumps(messages))
    call = json.loads(output)[1]["tool_calls"][0]["function"]
    assert call["name"] == "creer_facture"
    inner = json.loads(call["arguments"])
    assert inner == {"customer_name": "[REDACTED]", "siret": "[FR_SIRET]", "amount": 120}
    assert name not in output
    assert siret not in output


def test_unchanged_json_is_returned_verbatim(redactor: Redactor) -> None:
    text = '{"a":1,   "b": [1, 2, "rien"]}'
    assert redactor.redact_value(text) is text


def test_hostile_json(fake: Faker) -> None:
    redactor = make_redactor(max_chars=1_000_000)
    deep = "[" * 100_000 + "]" * 100_000
    assert redactor.redact_value(deep) == deep
    nested: object = {"contact": fake.email()}
    for _ in range(100):
        nested = {"child": nested}
    assert "@" not in json.dumps(redactor.redact_value(nested))


def test_numbers_and_other_types(redactor: Redactor) -> None:
    assert redactor.redact_value(int(NIR)) == "[FR_NIR]"
    assert redactor.redact_value(12345) == 12345
    assert redactor.redact_value(True) is True
    assert redactor.redact_value(3.14) == 3.14
    assert redactor.redact_value(None) is None
    assert redactor.redact_value(10**5000) == "[REDACTED]"
    assert redactor.redact_value(b"raw bytes") == "[REDACTED]"
    assert redactor.redact_value(object()) == "[REDACTED]"


def test_sequences_stay_homogeneous(redactor: Redactor) -> None:
    assert redactor.redact_value(["ok", 1]) == ["ok", "1"]
    output = redactor.redact_value(("jean@exemple.fr", 5))
    assert isinstance(output, tuple)
    assert output[0].startswith("[EMAIL:")
    assert output[1] == "5"
    assert redactor.redact_value([1, 2, 3]) == [1, 2, 3]


def test_attributes(fake: Faker) -> None:
    redactor = make_redactor(Policy.from_dict({"keys": {"drop": ["debug.*"]}}))
    email, siret = fake.email(), fake.siret().replace(" ", "")
    attributes = {
        "gen_ai.usage.input_tokens": 812,
        "gen_ai.request.model": "mistral-small",
        "gen_ai.input.messages": json.dumps([{"role": "user", "content": f"mail {email}"}]),
        "user.email": email,
        "enduser.id": "user-42",
        "customer.phone": "0612345678",
        "customer.siret": siret,
        "debug.payload": "anything",
        "flag": True,
        "nothing": None,
    }
    output = redactor.redact_attributes(attributes)
    assert output["gen_ai.usage.input_tokens"] == 812
    assert output["gen_ai.request.model"] == "mistral-small"
    assert email not in output["gen_ai.input.messages"]
    assert output["user.email"] == "[REDACTED]"
    assert TOKEN.fullmatch(output["enduser.id"])
    assert output["customer.phone"] == "[REDACTED]"
    assert output["customer.siret"] == "[FR_SIRET]"
    assert "debug.payload" not in output
    assert output["flag"] is True
    assert output["nothing"] is None
    assert redactor.redact_attributes(output) == output


def test_too_large(redactor: Redactor) -> None:
    assert redactor.redact_text("a" * 200_001) == "[TOO_LARGE]"
    assert redactor.stats.snapshot()[E.TOO_LARGE] == 1


def test_stats_count_entities(redactor: Redactor) -> None:
    redactor.redact_text("jean@exemple.fr et paul@exemple.fr")
    assert redactor.stats.snapshot() == {E.EMAIL: 2}
    redactor.stats.reset()
    assert redactor.stats.snapshot() == {}


def test_missing_key_uses_a_random_key() -> None:
    policy = Policy.default().replace(plugins=False, key_env=None)
    with pytest.warns(CaviardWarning, match="pseudonym key"):
        first = Redactor(policy)
    with pytest.warns(CaviardWarning):
        second = Redactor(policy)
    assert first.redact_text("jean@exemple.fr") != second.redact_text("jean@exemple.fr")


def test_mask_only_policy_needs_no_key() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Redactor(Policy.from_preset("strict").replace(plugins=False, key_env=None))


def test_key_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAVIARD_HMAC_KEY", TEST_KEY)
    from_env = Redactor(Policy.default().replace(plugins=False))
    expected = make_redactor().redact_text("jean@exemple.fr")
    assert from_env.redact_text("jean@exemple.fr") == expected


def test_key_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CAVIARD_HMAC_KEY", raising=False)
    key_file = tmp_path / "caviard.key"
    key_file.write_text(TEST_KEY + "\n", encoding="utf-8")
    redactor = Redactor(Policy.default().replace(plugins=False, key_file=str(key_file)))
    expected = make_redactor().redact_text("jean@exemple.fr")
    assert redactor.redact_text("jean@exemple.fr") == expected
    missing = Policy.default().replace(plugins=False, key_file=str(tmp_path / "absent.key"))
    with pytest.raises(PolicyError, match="key file"):
        Redactor(missing)


def test_short_key_is_rejected_without_being_echoed() -> None:
    with pytest.raises(PolicyError) as error:
        Redactor(Policy.default().replace(plugins=False), pseudonym_key="tooshortsecret")
    assert "tooshortsecret" not in str(error.value)


def test_custom_detector_with_hash() -> None:
    detector = Detector("ticket", "TICKET_ID", re.compile(r"TCK-[0-9]{6}"))
    policy = Policy.from_dict(
        {"preset": "none", "plugins": False, "entities": {"TICKET_ID": "hash"}}
    )
    redactor = Redactor(policy, extra_detectors=[detector], pseudonym_key=TEST_KEY)
    output = redactor.redact_text("ticket TCK-123456")
    assert TOKEN.fullmatch(output.split()[-1])
    assert redactor.redact_text(output) == output
