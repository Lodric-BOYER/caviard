from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
import yaml

from caviard import Action, OnError, Policy, PolicyError
from caviard.core.policy import PRESETS, normalize_field

TOML = """
preset = "standard"
on_error = "drop"

[pseudonym]
key_env = "MY_KEY"
length = 16

[keys]
allow = ["custom.*"]
drop = ["debug.*"]

[json]
sensitive_fields = ["numero_client"]

[entities]
IBAN = { action = "partial", keep_last = 4 }
FR_PHONE = "mask"
"""


def test_default_preset() -> None:
    policy = Policy.default()
    assert policy.preset == "standard"
    assert policy.rule("EMAIL").action is Action.HASH
    assert policy.rule("FR_NIR").action is Action.MASK
    assert policy.key_decision("gen_ai.usage.input_tokens") == "allow"
    assert policy.key_decision("gen_ai.input.messages") is None
    assert policy.key_decision("user.email") == "mask"
    assert policy.key_decision("enduser.id") == "hash"
    assert policy.is_sensitive_field("customerName")


@pytest.mark.parametrize("name", PRESETS)
def test_presets_load(name: str) -> None:
    assert Policy.from_preset(name).preset == name


def test_preset_differences() -> None:
    strict = Policy.from_preset("strict")
    assert strict.on_error is OnError.DROP
    assert strict.rule("EMAIL").action is Action.MASK
    assert strict.key_decision("enduser.id") == "mask"
    debug = Policy.from_preset("debug-local")
    assert debug.rule("FR_NIR").action is Action.HASH
    assert debug.rule("SECRET").action is Action.MASK
    none = Policy.from_preset("none")
    assert none.key_decision("gen_ai.usage.input_tokens") is None
    assert not none.is_sensitive_field("email")


def test_bare_constructor_is_safe() -> None:
    policy = Policy()
    assert policy.rule("EMAIL").action is Action.MASK
    assert policy.key_decision("anything") is None


@pytest.mark.parametrize("suffix", [".toml", ".yaml", ".json"])
def test_load_files(tmp_path: Path, suffix: str) -> None:
    data = tomllib.loads(TOML)
    path = tmp_path / f"policy{suffix}"
    if suffix == ".toml":
        path.write_text(TOML, encoding="utf-8")
    elif suffix == ".yaml":
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
    else:
        path.write_text(json.dumps(data), encoding="utf-8")
    policy = Policy.load(path)
    assert policy.on_error is OnError.DROP
    assert policy.key_env == "MY_KEY"
    assert policy.pseudonym_length == 16
    assert policy.key_decision("custom.anything") == "allow"
    assert policy.key_decision("gen_ai.usage.output_tokens") == "allow"  # preset list extended
    assert policy.key_decision("debug.trace") == "drop"
    assert policy.is_sensitive_field("numeroClient")
    assert policy.is_sensitive_field("email")
    assert policy.rule("IBAN").action is Action.PARTIAL
    assert policy.rule("IBAN").keep_last == 4
    assert policy.rule("FR_PHONE").action is Action.MASK


def test_drop_wins_over_allow() -> None:
    policy = Policy.from_dict({"keys": {"allow": ["x.*"], "drop": ["x.secret"]}})
    assert policy.key_decision("x.secret") == "drop"
    assert policy.key_decision("x.other") == "allow"


@pytest.mark.parametrize(
    ("data", "fragment"),
    [
        ({"unknown": 1}, "unknown"),
        ({"keys": {"alow": []}}, "keys.alow"),
        ({"entities": {"IBAN": {"acton": "mask"}}}, "entities.IBAN.acton"),
        ({"on_error": "explode"}, "on_error"),
        ({"max_chars": 10}, "max_chars"),
        ({"entities": {"FR_NIR": "obliterate"}}, "entities.FR_NIR"),
        ({"entities": {"FR_NIR": {"min_score": 2}}}, "min_score"),
        ({"entities": {"FR_NIR": {"keep_last": 20}}}, "keep_last"),
        ({"entities": {"bad-name": "mask"}}, "entities"),
        ({"version": 2}, "version"),
        ({"preset": "nope"}, "preset"),
        ({"default_action": "keep"}, "default_action"),
        ({"keys": {"allow": "not-a-list"}}, "keys.allow"),
        ({"pseudonym": {"length": 4}}, "pseudonym.length"),
        ({"plugins": "yes"}, "plugins"),
    ],
)
def test_invalid_policies(data: dict[str, object], fragment: str) -> None:
    with pytest.raises(PolicyError, match=fragment.replace(".", r"\.")):
        Policy.from_dict(data)


def test_errors_never_echo_values() -> None:
    for data in (
        {"pseudonym": {"key_env": "1secretvalue"}},
        {"entities": {"FR_NIR": "secretvalue"}},
        {"on_error": "secretvalue"},
    ):
        with pytest.raises(PolicyError) as error:
            Policy.from_dict(data)
        assert "secretvalue" not in str(error.value)


def test_invalid_files(tmp_path: Path) -> None:
    broken = tmp_path / "broken.toml"
    broken.write_text("preset = ", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid policy file"):
        Policy.load(broken)
    other = tmp_path / "policy.ini"
    other.write_text("", encoding="utf-8")
    with pytest.raises(PolicyError, match="must end in"):
        Policy.load(other)
    with pytest.raises(PolicyError, match="cannot read"):
        Policy.load(tmp_path / "absent.toml")
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    assert Policy.load(empty).preset == "standard"
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("keys: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid YAML"):
        Policy.load(bad_yaml)


def test_field_normalisation() -> None:
    assert normalize_field("Prénom") == "prenom"
    assert normalize_field("e-mail") == "email"
    assert normalize_field("DATE_DE_NAISSANCE") == "datedenaissance"
    assert normalize_field("customerName") == "customername"


def test_replace_recompiles_key_rules() -> None:
    policy = Policy.default().replace(allow_keys=("only.this",))
    assert policy.key_decision("only.this") == "allow"
    assert policy.key_decision("gen_ai.usage.input_tokens") is None


def test_allowed_otel_keys_are_explicit() -> None:
    # Instrumentations may copy the status description, an error message, into an attribute.
    policy = Policy.default()
    assert policy.key_decision("otel.scope.name") == "allow"
    assert policy.key_decision("otel.status_code") == "allow"
    assert policy.key_decision("otel.status_description") != "allow"
    # On server spans, the client sets server.address (the Host header): it is analysed.
    assert policy.key_decision("server.address") is None
    assert policy.key_decision("server.port") == "allow"
    assert policy.key_decision("client.address") != "allow"  # the end user's address


@pytest.mark.parametrize(
    "name",
    [
        "db_password",
        "client_secret",
        "x-api-key",
        "auth_token",
        "session_token",
        "secret_key",
        "AWS_SECRET_ACCESS_KEY",
        "privateKey",
        "Set-Cookie",
        "credentials",
        "proxy_authorization",
        "passphrase",
        "cvv",
        "mot_de_passe_admin",
    ],
)
def test_compound_secret_names_are_sensitive(name: str) -> None:
    assert Policy.default().is_sensitive_field(name)


@pytest.mark.parametrize(
    "name",
    [
        "billing_address",
        "shipping_address",
        "contact_email",
        "mobile_phone",
        "date_of_birth",
        "birthday",
        "patient_name",
        "client_name",
        "github_username",
        "customer_iban",
        "Prénom",
        "nom_de_famille",
        "tel_client",
        "mobile_number",
        "whatsapp",
    ],
)
def test_compound_personal_names_are_sensitive(name: str) -> None:
    assert Policy.default().is_sensitive_field(name)


@pytest.mark.parametrize(
    "name",
    [
        "input_tokens",
        "max_tokens",
        "token_count",
        "tokenizer",
        "token_type",
        "model",
        "model_name",
        "tool_name",
        "function_name",
        "display_name",
        "finish_reason",
    ],
)
def test_model_and_tool_names_and_token_counts_stay_readable(name: str) -> None:
    assert not Policy.default().is_sensitive_field(name)


def test_sensitive_field_patterns_in_a_policy() -> None:
    policy = Policy.from_dict({"json": {"sensitive_fields": ["*_dossier", "Numéro-*"]}})
    assert policy.is_sensitive_field("patient_dossier")
    assert policy.is_sensitive_field("numero_client")
    assert not policy.is_sensitive_field("dossier_id")
    assert not policy.is_sensitive_field("x" * 300 + "password")  # not a field name


@pytest.mark.parametrize(
    "key",
    [
        "http.request.header.authorization",
        "http.request.header.proxy_authorization",
        "http.request.header.x-api-key",
        "http.request.header.x_api_key",
        "http.request.header.api-key",
        "http.request.header.x_auth_token",
        "http.request.header.cookie",
        "http.response.header.set-cookie",
        "http.response.header.set_cookie",
        "http.request.header.ocp-apim-subscription-key",
    ],
)
def test_secret_headers_are_masked_in_both_spellings(key: str) -> None:
    assert Policy.default().key_decision(key) == "mask"


def test_other_headers_are_analysed() -> None:
    assert Policy.default().key_decision("http.request.header.content_type") is None
    assert Policy.default().key_decision("http.response.header.content-length") is None


def test_long_keys_are_not_cached() -> None:
    policy = Policy.default()
    key = "app." + "x" * 5_000
    assert policy.key_decision(key) is None
    assert key not in policy._decisions
