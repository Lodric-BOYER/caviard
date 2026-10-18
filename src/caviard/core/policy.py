"""Redaction policy: what is masked, pseudonymised or kept, per entity and per key.

A policy starts from a preset ("standard", "strict", "debug-local" or "none")
and is adjusted by a TOML, YAML or JSON file. Lists in the file extend the
preset; scalars and entity rules replace it.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import functools
import json
import re
import tomllib
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, TypeVar

from caviard.core import entities as E
from caviard.core.errors import PolicyError

__all__ = [
    "DEFAULT_ALLOW_KEYS",
    "DEFAULT_HASH_KEYS",
    "DEFAULT_MASK_KEYS",
    "DEFAULT_SENSITIVE_FIELDS",
    "PRESETS",
    "Action",
    "EntityRule",
    "KeyDecision",
    "OnError",
    "Policy",
    "normalize_field",
]


class Action(StrEnum):
    """What to do with a detected value."""

    MASK = "mask"  # [ENTITY]
    HASH = "hash"  # [ENTITY:token], the same value always gives the same token
    PARTIAL = "partial"  # [ENTITY:...1234], keeps the last characters
    KEEP = "keep"  # the detector is disabled


class OnError(StrEnum):
    """What integrations do with a span when redaction fails."""

    QUARANTINE = "quarantine"  # export it with every non-allowed attribute replaced
    DROP = "drop"  # do not export it


KeyDecision = Literal["allow", "mask", "hash", "drop"]


@dataclass(frozen=True)
class EntityRule:
    """Rule for one entity type."""

    action: Action = Action.MASK
    min_score: float = 0.0
    keep_last: int = 4


@functools.lru_cache(maxsize=4096)
def normalize_field(name: str) -> str:
    """Lowercase, strip accents, keep letters and digits: "Prénom" -> "prenom"."""
    decomposed = unicodedata.normalize("NFKD", name.lower())
    return "".join(char for char in decomposed if char.isascii() and char.isalnum())


# Attribute keys that never carry user content: exported unchanged.
DEFAULT_ALLOW_KEYS: tuple[str, ...] = (
    "gen_ai.operation.name",
    "gen_ai.provider.name",
    "gen_ai.system",
    "gen_ai.request.model",
    "gen_ai.request.temperature",
    "gen_ai.request.top_p",
    "gen_ai.request.top_k",
    "gen_ai.request.max_tokens",
    "gen_ai.request.seed",
    "gen_ai.request.frequency_penalty",
    "gen_ai.request.presence_penalty",
    "gen_ai.request.choice.count",
    "gen_ai.response.model",
    "gen_ai.response.id",
    "gen_ai.response.finish_reasons",
    "gen_ai.usage.*",
    "gen_ai.token.type",
    "gen_ai.tool.name",
    "gen_ai.tool.type",
    "gen_ai.tool.call.id",
    "gen_ai.agent.id",
    "gen_ai.agent.name",
    "gen_ai.conversation.id",
    "gen_ai.output.type",
    "llm.model_name",
    "llm.provider",
    "llm.system",
    "llm.token_count.*",
    "openinference.span.kind",
    "service.*",
    "telemetry.*",
    "otel.*",
    "http.request.method",
    "http.response.status_code",
    "error.type",
    "langfuse.observation.type",
    "langfuse.observation.level",
    "langfuse.observation.model.name",
    "langfuse.observation.usage_details",
    "langfuse.observation.cost_details",
    "langfuse.environment",
    "langfuse.release",
    "langfuse.version",
)
# Attribute keys whose whole value is replaced, without analysis.
DEFAULT_MASK_KEYS: tuple[str, ...] = (
    "user.email",
    "user.full_name",
    "user.name",
    "http.request.header.authorization",
    "http.request.header.cookie",
    "http.request.header.proxy-authorization",
    "http.request.header.x-api-key",
    "http.response.header.set-cookie",
)
# Attribute keys whose whole value is pseudonymised (correlation is kept).
DEFAULT_HASH_KEYS: tuple[str, ...] = ("enduser.id", "user.id")
# JSON fields (and last segments of attribute keys) whose value is replaced.
DEFAULT_SENSITIVE_FIELDS: tuple[str, ...] = (
    "email",
    "email_address",
    "mail",
    "courriel",
    "phone",
    "phone_number",
    "telephone",
    "tel",
    "mobile",
    "portable",
    "address",
    "street_address",
    "postal_address",
    "adresse",
    "first_name",
    "last_name",
    "full_name",
    "customer_name",
    "username",
    "prenom",
    "nom",
    "nom_complet",
    "birth_date",
    "date_of_birth",
    "dob",
    "date_naissance",
    "date_de_naissance",
    "iban",
    "nir",
    "ssn",
    "social_security_number",
    "numero_secu",
    "password",
    "passwd",
    "mot_de_passe",
    "mdp",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "authorization",
)


def _preset_standard() -> dict[str, Any]:
    return {
        "on_error": "quarantine",
        "max_chars": 200_000,
        "default_action": "mask",
        "keys": {
            "allow": list(DEFAULT_ALLOW_KEYS),
            "mask": list(DEFAULT_MASK_KEYS),
            "hash": list(DEFAULT_HASH_KEYS),
            "drop": [],
        },
        "json": {"max_depth": 4, "sensitive_fields": list(DEFAULT_SENSITIVE_FIELDS)},
        "entities": {E.EMAIL: "hash", E.FR_PHONE: "hash", E.IP_ADDRESS: "hash"},
    }


def _preset_strict() -> dict[str, Any]:
    preset = _preset_standard()
    preset["on_error"] = "drop"
    preset["keys"]["mask"] = [*DEFAULT_MASK_KEYS, *DEFAULT_HASH_KEYS]
    preset["keys"]["hash"] = []
    preset["json"]["max_depth"] = 6
    preset["entities"] = {}
    return preset


def _preset_debug_local() -> dict[str, Any]:
    preset = _preset_standard()
    preset["entities"] = {name: "hash" for name in E.BUILTIN if name not in (E.SECRET, E.JWT)}
    return preset


def _preset_none() -> dict[str, Any]:
    return {
        "keys": {"allow": [], "mask": [], "hash": [], "drop": []},
        "json": {"max_depth": 4, "sensitive_fields": []},
        "entities": {},
    }


_PRESET_FACTORIES: dict[str, Callable[[], dict[str, Any]]] = {
    "standard": _preset_standard,
    "strict": _preset_strict,
    "debug-local": _preset_debug_local,
    "none": _preset_none,
}
PRESETS: tuple[str, ...] = tuple(_PRESET_FACTORIES)

_TOP_KEYS = frozenset(
    {
        "version",
        "preset",
        "on_error",
        "max_chars",
        "default_action",
        "plugins",
        "pseudonym",
        "keys",
        "json",
        "entities",
    }
)
_SECTION_KEYS: dict[str, frozenset[str]] = {
    "pseudonym": frozenset({"key_env", "key_file", "length"}),
    "keys": frozenset({"allow", "mask", "hash", "drop"}),
    "json": frozenset({"max_depth", "sensitive_fields"}),
}
_ENTITY_RULE_KEYS = frozenset({"action", "min_score", "keep_last"})
_ENTITY_NAME = re.compile(r"[A-Z][A-Z_]{1,31}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_EnumT = TypeVar("_EnumT", bound=StrEnum)


@dataclass(frozen=True, eq=False)
class Policy:
    """Immutable redaction policy.

    Build it with :meth:`default`, :meth:`from_preset`, :meth:`from_dict` or
    :meth:`load`. The bare constructor gives the empty "none" preset: every
    detector masks, no key or field rule applies.
    """

    preset: str = "none"
    entities: Mapping[str, EntityRule] = field(default_factory=dict)
    default_action: Action = Action.MASK
    on_error: OnError = OnError.QUARANTINE
    max_chars: int = 200_000
    json_max_depth: int = 4
    sensitive_fields: frozenset[str] = frozenset()
    allow_keys: tuple[str, ...] = ()
    mask_keys: tuple[str, ...] = ()
    hash_keys: tuple[str, ...] = ()
    drop_keys: tuple[str, ...] = ()
    key_env: str | None = "CAVIARD_HMAC_KEY"
    key_file: str | None = None
    pseudonym_length: int = 12
    plugins: bool = True
    _matchers: tuple[tuple[KeyDecision, re.Pattern[str]], ...] = field(init=False, repr=False)
    _decisions: dict[str, KeyDecision | None] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        groups: tuple[tuple[KeyDecision, tuple[str, ...]], ...] = (
            ("drop", self.drop_keys),
            ("mask", self.mask_keys),
            ("hash", self.hash_keys),
            ("allow", self.allow_keys),
        )
        matchers = tuple(
            (decision, _compile_globs(patterns)) for decision, patterns in groups if patterns
        )
        object.__setattr__(self, "_matchers", matchers)
        object.__setattr__(self, "_decisions", {})
        object.__setattr__(
            self,
            "sensitive_fields",
            frozenset(normalize_field(name) for name in self.sensitive_fields),
        )

    # Construction

    @classmethod
    def default(cls) -> Policy:
        """The "standard" preset."""
        return cls.from_preset("standard")

    @classmethod
    def from_preset(cls, name: str = "standard") -> Policy:
        return cls.from_dict({"preset": name})

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> Policy:
        """Build a policy from parsed TOML, YAML or JSON content."""
        if data is None:
            data = {}
        if not isinstance(data, Mapping):
            raise PolicyError("policy: expected a table")
        _validate_shape(data)
        if data.get("version", 1) != 1:
            raise PolicyError("version: only version 1 is supported")
        preset = data.get("preset", "standard")
        if not isinstance(preset, str) or preset not in _PRESET_FACTORIES:
            raise PolicyError(f"preset: expected one of: {', '.join(PRESETS)}")
        merged = _merge(_PRESET_FACTORIES[preset](), data)
        return cls._build(preset, merged)

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        """Load a policy file (.toml, .yaml, .yml or .json)."""
        file = Path(path)
        try:
            text = file.read_text(encoding="utf-8")
        except OSError:
            raise PolicyError(f"cannot read the policy file {file.name!r}") from None
        suffix = file.suffix.lower()
        try:
            if suffix == ".toml":
                data = tomllib.loads(text)
            elif suffix in (".yaml", ".yml"):
                data = _load_yaml(text)
            elif suffix == ".json":
                data = json.loads(text)
            else:
                raise PolicyError("policy files must end in .toml, .yaml, .yml or .json")
        except (tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
            raise PolicyError(f"invalid policy file {file.name!r}: {exc}") from None
        return cls.from_dict(data)

    def replace(self, **changes: Any) -> Policy:
        """Return a copy with some fields changed."""
        return dataclasses.replace(self, **changes)

    # Queries

    def rule(self, entity: str) -> EntityRule:
        found = self.entities.get(entity)
        return found if found is not None else EntityRule(self.default_action)

    def key_decision(self, key: str) -> KeyDecision | None:
        """Decision for an attribute key; drop wins over mask, hash, then allow."""
        try:
            return self._decisions[key]
        except KeyError:
            pass
        decision = next((name for name, regex in self._matchers if regex.match(key)), None)
        if len(self._decisions) >= 4096:
            self._decisions.clear()
        self._decisions[key] = decision
        return decision

    def is_sensitive_field(self, name: str) -> bool:
        return bool(self.sensitive_fields) and normalize_field(name) in self.sensitive_fields

    @classmethod
    def _build(cls, preset: str, data: Mapping[str, Any]) -> Policy:
        keys = data.get("keys", {})
        json_section = data.get("json", {})
        pseudonym = data.get("pseudonym", {})
        key_env = pseudonym.get("key_env", "CAVIARD_HMAC_KEY")
        if key_env is not None and (
            not isinstance(key_env, str) or (key_env and not _ENV_NAME.fullmatch(key_env))
        ):
            raise PolicyError("pseudonym.key_env: expected an environment variable name")
        key_file = pseudonym.get("key_file")
        if key_file is not None and not isinstance(key_file, str):
            raise PolicyError("pseudonym.key_file: expected a file path")
        plugins = data.get("plugins", True)
        if not isinstance(plugins, bool):
            raise PolicyError("plugins: expected true or false")
        entities = {
            name: _entity_rule(rule, f"entities.{name}")
            for name, rule in data.get("entities", {}).items()
        }
        return cls(
            preset=preset,
            entities=entities,
            default_action=_choice(
                Action, data.get("default_action", "mask"), "default_action", (Action.KEEP,)
            ),
            on_error=_choice(OnError, data.get("on_error", "quarantine"), "on_error"),
            max_chars=_int(data.get("max_chars", 200_000), "max_chars", 1_000, 100_000_000),
            json_max_depth=_int(json_section.get("max_depth", 4), "json.max_depth", 0, 16),
            sensitive_fields=frozenset(
                _str_list(json_section.get("sensitive_fields", []), "json.sensitive_fields")
            ),
            allow_keys=tuple(_str_list(keys.get("allow", []), "keys.allow")),
            mask_keys=tuple(_str_list(keys.get("mask", []), "keys.mask")),
            hash_keys=tuple(_str_list(keys.get("hash", []), "keys.hash")),
            drop_keys=tuple(_str_list(keys.get("drop", []), "keys.drop")),
            key_env=key_env or None,
            key_file=key_file,
            pseudonym_length=_int(pseudonym.get("length", 12), "pseudonym.length", 8, 32),
            plugins=plugins,
        )


def _compile_globs(patterns: Iterable[str]) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{fnmatch.translate(pattern)})" for pattern in patterns))


def _load_yaml(text: str) -> Any:
    try:
        import yaml
    except ImportError:
        raise PolicyError("YAML policies need PyYAML: pip install 'caviard[yaml]'") from None
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise PolicyError(f"invalid YAML{where}") from None


def _check_keys(section: Mapping[Any, Any], allowed: frozenset[str], path: str) -> None:
    unknown = sorted(str(key) for key in section if key not in allowed)
    if unknown:
        prefix = f"{path}." if path else ""
        raise PolicyError(f"unknown policy key(s): {', '.join(prefix + key for key in unknown)}")


def _mapping(value: Any, path: str) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"{path}: expected a table")
    return value


def _validate_shape(data: Mapping[Any, Any]) -> None:
    _check_keys(data, _TOP_KEYS, "")
    for section, allowed in _SECTION_KEYS.items():
        if section in data:
            _check_keys(_mapping(data[section], section), allowed, section)
    if "entities" in data:
        for name, rule in _mapping(data["entities"], "entities").items():
            if not isinstance(name, str) or not _ENTITY_NAME.fullmatch(name):
                raise PolicyError(
                    "entities: names must be 2 to 32 uppercase letters or underscores"
                )
            if isinstance(rule, Mapping):
                _check_keys(rule, _ENTITY_RULE_KEYS, f"entities.{name}")
            elif not isinstance(rule, str):
                raise PolicyError(f"entities.{name}: expected an action name or a table")


def _merge(base: dict[str, Any], user: Mapping[str, Any]) -> dict[str, Any]:
    for name in ("on_error", "max_chars", "default_action", "plugins"):
        if name in user:
            base[name] = user[name]
    if "pseudonym" in user:
        base.setdefault("pseudonym", {}).update(user["pseudonym"])
    if "keys" in user:
        keys = base.setdefault("keys", {})
        for name, patterns in user["keys"].items():
            keys[name] = _extend(keys.get(name, []), patterns, f"keys.{name}")
    if "json" in user:
        section = base.setdefault("json", {})
        if "max_depth" in user["json"]:
            section["max_depth"] = user["json"]["max_depth"]
        if "sensitive_fields" in user["json"]:
            section["sensitive_fields"] = _extend(
                section.get("sensitive_fields", []),
                user["json"]["sensitive_fields"],
                "json.sensitive_fields",
            )
    if "entities" in user:
        base.setdefault("entities", {}).update(user["entities"])
    return base


def _extend(current: list[str], extra: Any, path: str) -> list[str]:
    return list(dict.fromkeys([*current, *_str_list(extra, path)]))


def _str_list(value: Any, path: str) -> list[str]:
    if (
        isinstance(value, str | bytes)
        or not isinstance(value, Iterable)
        or not all(isinstance(item, str) for item in value)
    ):
        raise PolicyError(f"{path}: expected a list of strings")
    return list(value)


def _int(value: Any, path: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise PolicyError(f"{path}: expected an integer between {low} and {high}")
    return value


def _choice(enum: type[_EnumT], value: Any, path: str, exclude: tuple[_EnumT, ...] = ()) -> _EnumT:
    allowed = [member.value for member in enum if member not in exclude]
    if not isinstance(value, str) or value not in allowed:
        raise PolicyError(f"{path}: expected one of: {', '.join(allowed)}")
    return enum(value)


def _entity_rule(value: Any, path: str) -> EntityRule:
    if isinstance(value, str):
        return EntityRule(_choice(Action, value, path))
    action = _choice(Action, value.get("action", "mask"), f"{path}.action")
    min_score = value.get("min_score", 0.0)
    if (
        isinstance(min_score, bool)
        or not isinstance(min_score, int | float)
        or not 0.0 <= min_score <= 1.0
    ):
        raise PolicyError(f"{path}.min_score: expected a number between 0 and 1")
    keep_last = _int(value.get("keep_last", 4), f"{path}.keep_last", 1, 8)
    return EntityRule(action, float(min_score), keep_last)
