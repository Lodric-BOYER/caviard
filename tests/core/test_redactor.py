from __future__ import annotations

import json
import re
import warnings
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import quote_plus

import pytest
from faker import Faker

from caviard import Action, CaviardWarning, Detector, EntityRule, Policy, PolicyError, Redactor
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


@pytest.mark.parametrize("levels", [100, 5_000, 20_000, 100_000])
def test_deep_json_fails_closed(fake: Faker, levels: int) -> None:
    # Whether the parser accepts these depths depends on the Python version and the
    # stack size (Python 3.14.8 on Linux parses 100,000 levels, 3.11 stops near
    # 1,000): either way a hidden field must not come back through the text path.
    redactor = make_redactor(max_chars=1_000_000)
    name = fake.name()
    hidden = json.dumps({"customer_name": name}, ensure_ascii=False)
    document = "[" * levels + hidden + "]" * levels
    output = redactor.redact_value(document)
    assert name not in output
    assert "[REDACTED]" in output
    assert len(output) < 200
    assert redactor.redact_value(output) == output


def test_hostile_json(fake: Faker) -> None:
    redactor = make_redactor(max_chars=1_000_000)
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


class _Contact:
    """An object whose text is personal data."""

    def __init__(self, email: str) -> None:
        self.email = email

    def __repr__(self) -> str:
        return self.email

    __str__ = __repr__


def _python_values(email: str) -> dict[str, object]:
    return {
        "tuple": {"contacts": (email, 1)},
        "set": {"contacts": {email}},
        "frozenset": {"contacts": frozenset({email})},
        "bytes": {"raw": email.encode()},
        "bytearray": {"raw": bytearray(email.encode())},
        "object": {"contact": _Contact(email)},
        "read-only mapping": {"contact": MappingProxyType({"to": email})},
        "key": {email: "vip"},
        "nested key": {"users": {email: {"role": "admin"}}},
        "tuple key": {(email, 1): "seen"},
        "tuples in lists": [[(email,)]],
    }


@pytest.mark.parametrize("case", list(_python_values("")))
def test_python_values_never_pass_through(redactor: Redactor, case: str) -> None:
    email = "jeanne.martin@exemple.fr"
    output = redactor.redact_value(_python_values(email)[case])
    assert email not in repr(output)
    assert redactor.redact_value(output) == output


def test_containers_keep_their_kind(redactor: Redactor) -> None:
    email = "jeanne.martin@exemple.fr"
    output = redactor.redact_value({"t": (email, 1), "s": {email}, "f": frozenset({email})})
    assert isinstance(output["t"], tuple)
    assert output["t"][1] == 1
    assert isinstance(output["s"], set)
    assert isinstance(output["f"], frozenset)
    assert next(iter(output["s"])).startswith("[EMAIL:")


def test_mapping_keys_are_redacted(redactor: Redactor, fake: Faker) -> None:
    email = fake.email()
    output = redactor.redact_value({"users": {email: {"role": "admin"}}})
    (key,) = output["users"]
    assert key.startswith("[EMAIL:")
    assert output["users"][key] == {"role": "admin"}
    text = redactor.redact_value(json.dumps({"users": {email: {"role": "admin"}}}))
    assert email not in text
    assert json.loads(text) == output


def test_keys_redacted_to_the_same_text_keep_their_values() -> None:
    redactor = make_redactor(Policy.from_preset("strict"))
    output = redactor.redact_value({"a@exemple.fr": 1, "b@exemple.fr": 2, "[EMAIL]": 3})
    assert output == {"[EMAIL]": 1, "[EMAIL]#2": 2, "[EMAIL]#3": 3}
    assert redactor.redact_value(output) == output


def test_sensitive_fields_replace_containers(redactor: Redactor, fake: Faker) -> None:
    value = {
        "customer_name": [fake.name()],
        "address": {"street": fake.street_address(), "city": "Lyon"},
        "email": [],
        "phone": None,
    }
    expected = {"customer_name": "[REDACTED]", "address": "[REDACTED]", "email": [], "phone": None}
    assert redactor.redact_value(value) == expected
    assert json.loads(redactor.redact_value(json.dumps(value))) == expected


def test_integral_floats_are_checked_like_integers(redactor: Redactor) -> None:
    assert redactor.redact_value(float(int(NIR))) == "[FR_NIR]"
    assert redactor.redact_value({"n": float(int(NIR))}) == {"n": "[FR_NIR]"}
    assert redactor.redact_value(1e12) == 1e12
    assert redactor.redact_value(0.5) == 0.5
    assert redactor.redact_value(float("inf")) == float("inf")


@pytest.mark.parametrize(("encodings", "walked"), [(4, True), (5, False)])
def test_json_encoded_past_max_depth_is_replaced(
    redactor: Redactor, fake: Faker, encodings: int, walked: bool
) -> None:
    # json.max_depth is 4: up to four encodings are walked, field by field.
    name = fake.name()
    payload = json.dumps({"customer_name": name}, ensure_ascii=False)
    for _ in range(encodings - 1):
        payload = json.dumps({"payload": payload}, ensure_ascii=False)
    output = redactor.redact_value(payload)
    assert name not in output
    innermost = output
    for _ in range(encodings - 1):
        innermost = json.loads(innermost)["payload"]
    assert innermost == ('{"customer_name": "[REDACTED]"}' if walked else "[REDACTED]")
    assert redactor.redact_value(output) == output


def test_json_decoding_can_be_turned_off(fake: Faker) -> None:
    redactor = make_redactor(json_max_depth=0)
    text = json.dumps({"customer_name": "Jeanne", "mail": fake.email()}, separators=(",", ":"))
    # Read as text, not decoded (the compact layout stays), yet field names still apply;
    # a value that a detector finds whole keeps the detector's type.
    output = redactor.redact_value(text)
    assert output.startswith('{"customer_name":"[REDACTED]","mail":"[EMAIL:')
    assert TOKEN.fullmatch(json.loads(output)["mail"])


def test_json_strings_are_decoded(redactor: Redactor, fake: Faker) -> None:
    # Langfuse encodes every metadata value as JSON: a document becomes a JSON string.
    name, email = fake.name(), fake.email()
    document = json.dumps({"customer_name": name, "plan": "pro"}, ensure_ascii=False)
    output = redactor.redact_value(json.dumps(document, ensure_ascii=False))
    assert name not in output
    assert json.loads(json.loads(output)) == {"customer_name": "[REDACTED]", "plan": "pro"}

    sentence = redactor.redact_value(json.dumps(f"écrire à {email}", ensure_ascii=False))
    assert json.loads(sentence).startswith("écrire à [EMAIL:")
    assert email not in sentence
    assert redactor.redact_value('"rien à signaler"') == '"rien à signaler"'


@pytest.mark.parametrize(
    "render",
    [lambda value: json.dumps(value, ensure_ascii=False), repr],
    ids=["json", "python"],
)
def test_payloads_quoted_in_a_text(redactor: Redactor, fake: Faker, render: Any) -> None:
    name = fake.name()
    payload = {"customer_name": name, "items": [{"sku": "A-12", "qty": 2}]}
    text = f"appel de creer_facture avec {render(payload)} terminé"

    output = redactor.redact_value(text)

    redacted = {"customer_name": "[REDACTED]", "items": payload["items"]}
    assert output == f"appel de creer_facture avec {render(redacted)} terminé"
    assert redactor.redact_value(output) == output


def test_payloads_that_are_no_literal_are_read_as_text(redactor: Redactor, fake: Faker) -> None:
    name = fake.name()
    text = f"args {{'customer_name': '{name}', 'when': datetime.date(2026, 10, 18)}}"
    output = redactor.redact_value(text)
    assert output == "args {'customer_name': '[REDACTED]', 'when': datetime.date(2026, 10, 18)}"


@pytest.mark.parametrize(
    "template",
    [
        "Contact(customer_name='{v}', plan='pro')",
        "customer_name='{v}' plan='pro'",
        'level=info customer_name="{v}" plan=pro',
        "GET /factures?customer_name={q}&plan=pro",
        "customer_name: '{v}'",
        '{{"customer_name": "{v}", "plan": "pr',
        '{{"customer_name": "{v}',
    ],
    ids=["dataclass", "pydantic", "logfmt", "query", "yaml", "truncated", "cut-in-value"],
)
def test_values_written_after_sensitive_field_names(
    redactor: Redactor, fake: Faker, template: str
) -> None:
    name = fake.name()
    text = template.format(v=name, q=quote_plus(name))
    output = redactor.redact_value(text)
    assert output == template.format(v="[REDACTED]", q="[REDACTED]")


@pytest.mark.parametrize(
    "text",
    [
        '{{"password": "{secret}", "password": "[REDACTED]"}}',
        '[{{"a": 1}}, {{"note": "clé {secret}", "note": "ok"}}]',
        'appel avec {{"note": "clé {secret}", "note": "ok"}} terminé',
        "appel avec {{'note': 'clé {secret}', 'note': 'ok'}} terminé",
    ],
    ids=["json", "json-nested", "json-in-text", "python-in-text"],
)
def test_repeated_keys_never_keep_a_value_in_clear(redactor: Redactor, text: str) -> None:
    # A parser keeps the last value of a repeated key: the others must not survive either.
    secret = "sk-proj-" + "Ab1" * 12
    output = redactor.redact_value(text.format(secret=secret))
    assert secret not in output
    assert redactor.redact_value(output) == output
    assert "Hunter2" not in redactor.redact_value('{"password": "Hunter2", "password": "x"}')


@pytest.mark.parametrize(
    "template",
    [
        "request.body.payload.data.attributes.customer.contact.details.customer_name='{v}'",
        'customer_name="{first}\n{last}"',
        "customer_name='{first}\n{last}'",
    ],
    ids=["long-dotted-path", "double-quotes-over-lines", "single-quotes-over-lines"],
)
def test_values_after_field_names_in_harder_forms(
    redactor: Redactor, fake: Faker, template: str
) -> None:
    first, last = fake.first_name(), fake.last_name()
    text = template.format(v=f"{first} {last}", first=first, last=last)
    output = redactor.redact_value(text)
    assert first not in output
    assert last not in output


@pytest.mark.parametrize(
    "text",
    [
        "Le champ customer_name est obligatoire.",
        "nom_complet=",
        "customer_name: str",
        "def create(email: str, password: str | None = None) -> User:",
        "mobile: true, email=None",
        "token == expected",
    ],
)
def test_field_names_without_a_value_are_left_alone(redactor: Redactor, text: str) -> None:
    # Flags, nulls and type annotations hold no data.
    assert redactor.redact_value(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("customer_name: requis", "customer_name: [REDACTED]"),
        ("email : voir plus bas", "email : [REDACTED]"),
    ],
)
def test_values_after_field_names_in_prose_are_replaced(
    redactor: Redactor, text: str, expected: str
) -> None:
    # "Adresse : 12 rue des Lilas" cannot be told apart from these: redacting more wins.
    assert redactor.redact_value(text) == expected


def test_attribute_sequences_stay_homogeneous(redactor: Redactor) -> None:
    attributes = redactor.redact_attributes(
        {"a": ["ok", 1], "b": ("jean@exemple.fr", 5), "c": [1, 2, 3]}
    )
    assert attributes["a"] == ["ok", "1"]
    assert isinstance(attributes["b"], tuple)
    assert attributes["b"][0].startswith("[EMAIL:")
    assert attributes["b"][1] == "5"
    assert attributes["c"] == [1, 2, 3]
    # Other values keep their types: a log body or a JSON document may mix them.
    assert redactor.redact_value(["ok", 1]) == ["ok", 1]


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


def test_key_rules_win_over_field_names(fake: Faker) -> None:
    policy = Policy.from_dict({"keys": {"hash": ["app.contact_email"], "allow": ["app.email"]}})
    redactor = make_redactor(policy)
    email = fake.email()
    output = redactor.redact_attributes({"app.contact_email": email, "app.email": "support"})
    assert TOKEN.fullmatch(output["app.contact_email"])  # pseudonymised, as asked
    assert output["app.email"] == "support"


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


def test_warnings_point_at_the_caller() -> None:
    policy = Policy.default().replace(plugins=False, key_env=None)
    with pytest.warns(CaviardWarning) as caught:
        Redactor(policy.replace(entities={**policy.entities, "NOPE": EntityRule(Action.MASK)}))
    assert [Path(w.filename).name for w in caught] == ["test_redactor.py", "test_redactor.py"]


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


def test_binary_key_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CAVIARD_HMAC_KEY", raising=False)
    raw = bytes([0x9F, 0xFF]) + bytes(range(1, 31))  # not UTF-8, as `openssl rand 32` writes
    key_file = tmp_path / "caviard.key"
    key_file.write_bytes(raw)
    redactor = Redactor(Policy.default().replace(plugins=False, key_file=str(key_file)))
    expected = Redactor(Policy.default().replace(plugins=False), pseudonym_key=raw)
    assert redactor.redact_text("jean@exemple.fr") == expected.redact_text("jean@exemple.fr")
    key_file.write_bytes(raw[:8])  # too short: refused without showing the bytes
    with pytest.raises(PolicyError) as error:
        Redactor(Policy.default().replace(plugins=False, key_file=str(key_file)))
    assert "\\x9f" not in repr(error.value)
    assert "\x9f" not in str(error.value)


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


STREET = "12 rue des Lilas"  # a synthetic street


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        (
            "method=GET path=/oauth/callback?token={t}&state=1",
            "method=GET path=/oauth/callback?token=[REDACTED]&state=1",
        ),
        (
            "level=info msg=\"update customer_name='{v}'\"",
            "level=info msg=\"update customer_name='[REDACTED]'\"",
        ),
        (
            "url=https://api.exemple.fr/v1/customers?customer_name={q}",
            "url=https://api.exemple.fr/v1/customers?customer_name=[REDACTED]",
        ),
    ],
    ids=["query-in-a-value", "pair-in-a-message", "query-in-a-url"],
)
def test_pairs_inside_other_values(
    redactor: Redactor, fake: Faker, template: str, expected: str
) -> None:
    name = fake.name()
    text = template.format(v=name, q=quote_plus(name), t="Zm9vYmFyYmF6cXV4MTIzNDU2")
    assert redactor.redact_value(text) == expected


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ("created customer_name={v} plan=pro", "created customer_name=[REDACTED] plan=pro"),
        ("address={s}, 69001 Lyon", "address=[REDACTED]"),
        ("address={s}, 69001 Lyon.", "address=[REDACTED]."),
        (
            "Customer(customer_id=42, address=Address(street='{s}', city='Lyon'))",
            "Customer(customer_id=42, address=[REDACTED])",
        ),
        ("Order(id=7, address=['{s}', 'Lyon'])", "Order(id=7, address=[REDACTED])"),
        ("customer_name    =    '{v}'", "customer_name    =    '[REDACTED]'"),
        ("'customer_name' => '{v}'", "'customer_name' => '[REDACTED]'"),
        ("address: {s}", "address: [REDACTED]"),
        ("**Nom :** {v}", "**Nom :** [REDACTED]"),
        ("Adresse" + chr(0xA0) + ": {s}", "Adresse" + chr(0xA0) + ": [REDACTED]"),
        ("customer_name={v}\nplan=pro", "customer_name=[REDACTED]\nplan=pro"),
        ("log.info: customer_name={v}, age=42", "log.info: customer_name=[REDACTED], age=42"),
    ],
    ids=[
        "bare-with-spaces",
        "address",
        "end-of-sentence",
        "nested-repr",
        "list",
        "aligned",
        "arrow",
        "yaml",
        "markdown",
        "no-break-space",
        "line-end",
        "next-field",
    ],
)
def test_whole_values_after_sensitive_names(
    redactor: Redactor, fake: Faker, template: str, expected: str
) -> None:
    text = template.format(v=fake.name(), s=STREET)
    output = redactor.redact_value(text)
    assert output == expected
    assert redactor.redact_value(output) == output


def test_values_that_go_on_after_brackets(redactor: Redactor) -> None:
    # The phone detector finds the whole value, so its type is kept.
    assert redactor.redact_value("Tél : (+33) 6 12 34 56 78").startswith("Tél : [FR_PHONE:")
    assert redactor.redact_value("phone: (555) 123-4567") == "phone: [REDACTED]"


@pytest.mark.parametrize(
    "template",
    [
        "password=[SECRET]{secret}",
        "Authorization: Bearer [SECRET]{secret}",
        "Bearer [SECRET]{secret}",
        "-----BEGIN PRIVATE KEY-----\n[REDACTED]{secret}\n-----END PRIVATE KEY-----",
        "customer_name=[EMAIL]{secret} plan=pro",
        "customer_name='Jean [EMAIL] {secret}'",
    ],
)
def test_placeholders_never_shield_a_value(redactor: Redactor, template: str) -> None:
    secret = "Zm9vYmFyYmF6cXV4MTIzNDU2"
    output = redactor.redact_value(template.format(secret=secret))
    assert secret not in output
    assert redactor.redact_value(output) == output


def test_placeholder_shaped_keys_are_no_exemption(redactor: Redactor, fake: Faker) -> None:
    name = fake.name()
    output = redactor.redact_value(json.dumps({"[PASSWORD]": "Hunter2Hunter2", "[NOM]": name}))
    assert json.loads(output) == {"[PASSWORD]": "[REDACTED]", "[NOM]": "[REDACTED]"}
    # Keys that a first pass redacted stay as they are, values included (idempotence).
    strict = make_redactor(Policy.from_preset("strict"))
    assert strict.redact_value({"[EMAIL]": "ok", "[IBAN]#2": "ok"}) == {
        "[EMAIL]": "ok",
        "[IBAN]#2": "ok",
    }


def test_redacted_keys_never_become_field_names(redactor: Redactor, fake: Faker) -> None:
    # "FR76... }" redacted is "[IBAN] }", which reads "iban" once the placeholder is
    # ignored: its value must not be replaced on a second pass when the first kept it.
    value = {f"{fake.iban()} }}": "rien", f"mail {fake.email()}": {"nom_x": "rien"}}
    once = redactor.redact_value(value)
    assert sorted(once.values(), key=str) == sorted(value.values(), key=str)
    assert redactor.redact_value(once) == once


def test_redaction_never_grows_a_value_past_max_chars() -> None:
    redactor = make_redactor(max_chars=1_000)
    phones = [f"06123456{index:02d}" for index in range(60)]
    for value in (json.dumps(phones, separators=(",", ":")), " ".join(phones)):
        assert len(value) <= 1_000
        once = redactor.redact_value(value)
        assert once == "[TOO_LARGE]"  # the pseudonyms are longer than the numbers
        assert redactor.redact_value(once) == once

    document = {f"k{index}": index for index in range(100)} | {"mail": "jean@exemple.fr"}
    assert len(json.dumps(document)) > 1_000 >= len(json.dumps(document, separators=(",", ":")))
    output = redactor.redact_value(json.dumps(document, separators=(",", ":")))
    assert len(output) <= 1_000
    assert ", " not in output  # written compact to fit
    assert json.loads(output)["mail"] == "[REDACTED]"
    assert redactor.redact_value(output) == output


def test_lone_surrogates_stay_escaped(redactor: Redactor) -> None:
    escape = chr(92) + "ud800"  # a JSON escape that decodes to a lone surrogate
    output = redactor.redact_value('{"note": "' + escape + ' jean@exemple.fr"}')
    output.encode("utf-8")  # exporters encode the text: it must hold no lone surrogate
    assert "jean@" not in output
    assert escape in output
    assert redactor.redact_value(output) == output


def test_objects_after_many_braces_are_still_read(redactor: Redactor) -> None:
    payload = f"args={{'address': ['{STREET}', 'Lyon']}}"
    assert STREET not in redactor.redact_value("{} " * 300 + payload)
    code = "function f(x) { if (x) { return {a: 1}; } }\n" * 40
    assert STREET not in redactor.redact_value(code + "tool " + payload)


def test_disguised_characters_hide_nothing(redactor: Redactor, fake: Faker) -> None:
    def fullwidth(text: str) -> str:
        return "".join(chr(0xFF10 + int(char)) if char.isdigit() else char for char in text)

    zero_width, no_break, en_dash, acute = chr(0x200B), chr(0xA0), chr(0x2013), chr(0x301)
    same = [
        (f"mail jean{zero_width}.dupont@exemple.fr", "mail jean.dupont@exemple.fr"),
        ("tél " + fullwidth("06 12 34 56 78"), "tél 06 12 34 56 78"),
        ("tél " + en_dash.join(["06", "12", "34", "56", "78"]), "tél 06 12 34 56 78"),
        ("jean" + chr(0xFF20) + "exemple" + chr(0xFF0E) + "fr", "jean@exemple.fr"),
        (f"jose{acute}@exemple.es", "josé@exemple.es"),
    ]
    for disguised, plain in same:
        # Same placeholder, same pseudonym: the variant is the same value.
        assert redactor.redact_text(disguised) == redactor.redact_text(plain)
    iban = fake.iban()
    grouped = no_break.join(iban[i : i + 4] for i in range(0, len(iban), 4))
    assert redactor.redact_text(f"IBAN{no_break}: {grouped}") == f"IBAN{no_break}: [IBAN]"
    assert redactor.redact_text("secu " + fullwidth(NIR)) == "secu [FR_NIR]"


@pytest.mark.parametrize(
    "mark", [chr(0x200E), chr(0x200F), chr(0x2060)], ids=["lrm", "rlm", "word-joiner"]
)
def test_invisible_characters_never_glue_a_value_to_the_next_word(
    redactor: Redactor, fake: Faker, mark: str
) -> None:
    iban = fake.iban()
    text = f"tel {mark}0612345678{mark}Tel fixe, IBAN {iban}{mark}Merci, fixe 0145678901{mark}1"
    output = redactor.redact_text(text)
    assert "0612345678" not in output
    assert iban not in output
    assert "0145678901" not in output
    assert f"{mark}Tel fixe, IBAN [IBAN]{mark}Merci" in output  # the next word stays
    assert output.count("[FR_PHONE:") == 2


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("address=12 rue des Lilas (batiment B) 69001 Lyon", "address=[REDACTED]"),
        ("address: 3 allee des Pins [Residence Azur] 13008 Marseille", "address: [REDACTED]"),
        ("full_name=Camille (Cam) Martin, plan=pro", "full_name=[REDACTED], plan=pro"),
    ],
    ids=["parentheses", "square-brackets", "nickname"],
)
def test_bare_values_go_on_after_inner_brackets(
    redactor: Redactor, text: str, expected: str
) -> None:
    output = redactor.redact_value(text)
    assert output == expected
    assert redactor.redact_value(output) == output


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "address='12 rue de l'Eglise Saint-Paul, 69005 Lyon' city=Lyon",
            "address='[REDACTED]' city=Lyon",
        ),
        ("customer_name='Camille O'Neil'", "customer_name='[REDACTED]'"),
        (
            'customer_name="Camille Mar\naddress="12 rue des Lilas"',
            'customer_name="[REDACTED]\naddress="[REDACTED]"',
        ),
    ],
    ids=["apostrophe", "apostrophe-in-a-name", "quote-cut-off"],
)
def test_quoted_values_end_at_their_own_quote(redactor: Redactor, text: str, expected: str) -> None:
    output = redactor.redact_value(text)
    assert output == expected
    assert redactor.redact_value(output) == output


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "user[password]=Hunter2Hunter2&user[address]=12+rue+des+Lilas",
            "user[password]=[SECRET]&user[address]=[REDACTED]",
        ),
        (
            "user%5Bpassword%5D=Hunter2Hunter2&user%5Baddress%5D=12+rue+des+Lilas",
            "user%5Bpassword%5D=[SECRET]&user%5Baddress%5D=[REDACTED]",
        ),
        ("card[cvc]=123", "card[cvc]=[REDACTED]"),
        ("[INFO]customer_name=Camille Martin", "[INFO]customer_name=[REDACTED]"),
    ],
    ids=["form-body", "url-encoded", "card", "after-a-log-level"],
)
def test_names_in_bracket_notation(redactor: Redactor, text: str, expected: str) -> None:
    # Rails, PHP and qs form bodies; user[password] is Devise's login field.
    output = redactor.redact_value(text)
    assert output == expected
    assert redactor.redact_value(output) == output


def test_session_and_token_names(redactor: Redactor) -> None:
    payload = {
        "token_value": "opaque-1",
        "tokens": {"refresh": "opaque-2"},
        "sessionid": "opaque-3",
        "sid": "opaque-4",
        "csrf_token": "opaque-5",
    }
    output = redactor.redact_value(json.dumps(payload))
    assert "opaque" not in output
    assert redactor.redact_value("token_value=Zm9vYmFyYmF6cXV4MTIzNDU2") == "token_value=[REDACTED]"
    # A cookie line is read to its end, however long.
    cookie = "Cookie: " + "theme=dark; " * 60 + "JSESSIONID=ABCDEF0123456789"
    assert redactor.redact_value(cookie) == "Cookie: [REDACTED]"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("customer_name=List, Camille Martin", "customer_name=[REDACTED]"),
        ('customer_name: str = "Camille Martin"', "customer_name: [REDACTED]"),
        ("customer_name=None", "customer_name=None"),
        ("customer_name: Optional[str]", "customer_name: Optional[str]"),
    ],
    ids=["word-then-value", "annotation-with-default", "null", "annotation"],
)
def test_only_whole_values_are_exempt(redactor: Redactor, text: str, expected: str) -> None:
    assert redactor.redact_value(text) == expected


def test_findings_on_disguised_text_point_at_the_original(redactor: Redactor) -> None:
    text = "écrire à " + chr(0x200B) * 3 + "jean" + chr(0x200B) + ".dupont@exemple.fr, merci"
    (finding,) = redactor.findings(text)
    assert text[finding.start : finding.end] == "jean" + chr(0x200B) + ".dupont@exemple.fr"
