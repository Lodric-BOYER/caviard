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
