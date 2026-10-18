"""Offline audit of exported traces and logs: which personal data they hold, and where.

The audit runs the redaction engine on every value and keeps only counts,
entity types and key names, themselves redacted. A summary never contains an
analysed value, so it can be shared, for example with a DPO. The optional
examples are the exception: they show redacted text around each finding.
"""

from __future__ import annotations

import datetime
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from caviard import __version__
from caviard.audit.readers import Field, FileStats, Record, read
from caviard.core import entities as E
from caviard.core.policy import Action, EntityRule, Policy
from caviard.core.redactor import Redactor

__all__ = ["ENTITY_LABELS", "KIND_LABELS", "Auditor", "propose_policy"]

ENTITY_LABELS: dict[str, str] = {
    E.SECRET: "Secret (API key, token, password)",
    E.JWT: "JSON Web Token",
    E.EMAIL: "Email address",
    E.FR_NIR: "French social security number (NIR)",
    E.IBAN: "IBAN",
    E.CARD: "Payment card number",
    E.FR_SIRET: "SIRET (French establishment number)",
    E.FR_SIREN: "SIREN (French company number)",
    E.FR_RPPS: "RPPS (French health professional number)",
    E.FR_PHONE: "French phone number",
    E.IP_ADDRESS: "IP address",
    E.REDACTED: "Sensitive field (name, address, birth date...)",
}
KIND_LABELS: dict[str, str] = {
    "span": "spans",
    "log": "log records",
    "record": "JSON objects",
    "text": "text lines",
}
# Sources whose keys are attribute or field names, the targets of key rules.
_KEYED = frozenset({"span", "event", "link", "resource", "log", "record"})
_PLACEHOLDER = re.compile(r"\[[A-Z][A-Z_]{1,31}(?::[^\]\s]{1,40})?\]")
_GLOB_CHARS = re.compile(r"([*?\[])")
# Whole values of these types are worth pseudonymising: correlation helps debugging.
_CORRELATED = frozenset({E.EMAIL, E.FR_PHONE, E.IP_ADDRESS})
_COVERED = frozenset({"mask", "hash", "drop", "field"})  # rules that replace the whole value
_WHOLE_SHARE = 0.8  # share of whole-value findings that makes a key a key-rule candidate
_MAX_LOCATIONS = 2_000
_MAX_GROUPS = 200
_MAX_ROWS = 200
_TEXT_CACHE = 10_000
_WINDOW = 50  # characters of context kept on each side of an example placeholder
_OTHER_KEYS = "(other keys)"
_OTHER_GROUP = "(other)"


@dataclass(frozen=True, order=True)
class Location:
    source: str
    key: str  # digit segments replaced by "*", then redacted
    detail: str = ""


@dataclass
class LocationStats:
    values: int = 0
    affected: int = 0
    whole: int = 0  # values that were entirely one identifier
    findings: Counter[str] = field(default_factory=Counter)
    rule: str | None = None  # key rule of the audited policy, or "field" (sensitive name)
    pattern: str | None = None  # key glob for a policy; None when the key holds personal data


@dataclass
class GroupStats:
    records: int = 0
    affected: int = 0
    findings: int = 0


class Auditor:
    """Accumulates findings over records; ``summary()`` gives the shareable result."""

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        policy_source: str | None = None,
        examples: int = 0,
    ) -> None:
        self.policy = policy if policy is not None else Policy.default()
        self.policy_source = policy_source
        self._engine = Redactor(_analysis_policy(self.policy))
        self._examples_limit = max(0, examples)
        self.files: list[FileStats] = []
        self.records: Counter[str] = Counter()
        self.affected: Counter[str] = Counter()
        self.findings: Counter[str] = Counter()
        self.entity_records: Counter[str] = Counter()
        self.locations: dict[Location, LocationStats] = {}
        self.services: dict[str, GroupStats] = {}
        self.scopes: dict[str, GroupStats] = {}
        self.examples: dict[str, list[str]] = {}
        self.skipped: Counter[str] = Counter()
        self.personal_keys = 0
        self._texts: dict[str, str] = {}

    # Input

    def add_file(self, path: Path, fmt: str = "auto") -> FileStats:
        stats = FileStats(path.name)
        self.files.append(stats)
        for record in read(path, fmt, stats):
            self.add(record)
        self.skipped["unreadable"] += stats.unreadable
        return stats

    def add(self, record: Record) -> Counter[str]:
        """Analyse one record; returns its findings per entity."""
        found: Counter[str] = Counter()
        for item in record.fields:
            found.update(self._analyse(item))
        self.findings.update(found)
        if record.kind == "resource":  # shared by many spans: not counted as a record
            return found
        self.records[record.kind] += 1
        if found:
            self.affected[record.kind] += 1
            self.entity_records.update(found.keys())
        for name, groups in ((record.service, self.services), (record.scope, self.scopes)):
            if name:
                group = self._group(groups, name)
                group.records += 1
                group.affected += 1 if found else 0
                group.findings += sum(found.values())
        return found

    # Output

    def summary(self) -> dict[str, Any]:
        """JSON-ready result: counts, entity types and redacted key names only."""
        total = sum(self.records.values())
        affected = sum(self.affected.values())
        ranked = sorted(
            ((loc, stats) for loc, stats in self.locations.items() if stats.findings),
            key=lambda item: (-sum(item[1].findings.values()), item[0]),
        )
        suggestions = {loc: _suggestion(stats) for loc, stats in ranked}
        summary: dict[str, Any] = {
            "caviard_version": __version__,
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "policy": {"preset": self.policy.preset, "file": self.policy_source},
            "files": [
                {
                    "name": f.name,
                    "format": f.format,
                    "records": f.records,
                    "unreadable": f.unreadable,
                }
                for f in self.files
            ],
            "records": {
                "total": total,
                "affected": affected,
                "by_kind": {
                    kind: {"records": count, "affected": self.affected[kind]}
                    for kind, count in sorted(self.records.items())
                },
            },
            "entities": [
                {
                    "entity": entity,
                    "label": ENTITY_LABELS.get(entity, entity),
                    "findings": count,
                    "records": self.entity_records[entity],
                    "action": self._action(entity),
                }
                for entity, count in sorted(self.findings.items(), key=lambda i: (-i[1], i[0]))
            ],
            "locations": [
                {
                    "source": loc.source,
                    "detail": loc.detail,
                    "key": loc.key,
                    "values": stats.values,
                    "affected": stats.affected,
                    "whole": stats.whole,
                    "findings": dict(sorted(stats.findings.items(), key=lambda i: (-i[1], i[0]))),
                    "rule": stats.rule,
                    "suggestion": suggestions[loc],
                }
                for loc, stats in ranked[:_MAX_ROWS]
            ],
            "more_locations": max(0, len(ranked) - _MAX_ROWS),
            "services": _groups(self.services),
            "scopes": _groups(self.scopes),
            "skipped": {
                name: self.skipped[name] for name in ("too_large", "binary", "errors", "unreadable")
            },
            "warnings": self._warnings(ranked, suggestions),
        }
        if self._examples_limit:
            summary["examples"] = {entity: list(items) for entity, items in self.examples.items()}
        summary["proposed_policy"] = propose_policy(
            self.policy.preset,
            mask=[s.pattern for loc, s in ranked if suggestions[loc] == "mask" and s.pattern],
            hash_=[s.pattern for loc, s in ranked if suggestions[loc] == "hash" and s.pattern],
            records=total,
            generated=summary["generated_at"][:10],
        )
        return summary

    # Internals

    def _analyse(self, item: Field) -> Counter[str]:
        value = item.value
        if value is None or isinstance(value, bool | float) or value in ("", [], {}):
            return Counter()
        if isinstance(value, bytes):
            self.skipped["binary"] += 1
            return Counter()
        stats = self._location(item)
        stats.values += 1
        engine = self._engine
        engine.stats.reset()
        try:
            redacted = engine.redact_value(value, item.key)
        except Exception:  # what the integrations quarantine
            self.skipped["errors"] += 1
            return Counter()
        counts: Counter[str] = Counter(engine.stats.snapshot())
        self.skipped["too_large"] += counts.pop(E.TOO_LARGE, 0)
        whole = isinstance(redacted, str) and _PLACEHOLDER.fullmatch(redacted) is not None
        if not counts and item.attribute and self.policy.is_sensitive_field(_last(item.key)):
            counts[E.REDACTED] = 1  # replaced at export because of its key name
            whole = True
        if counts:
            stats.affected += 1
            stats.whole += 1 if whole else 0
            stats.findings.update(counts)
            self._sample(redacted, counts)
        return counts

    def _location(self, item: Field) -> LocationStats:
        if item.attribute:
            display, pattern = _normalise(item.key)
        else:
            display, pattern = item.key, None
        key = self._safe(display)
        if key != display:  # the key itself holds personal data: never suggest it
            pattern = None
        detail = self._safe(item.detail) if item.detail else ""
        location = Location(item.source, key, detail)
        stats = self.locations.get(location)
        if stats is not None:
            return stats
        if len(self.locations) >= _MAX_LOCATIONS:
            return self.locations.setdefault(Location(item.source, _OTHER_KEYS), LocationStats())
        if item.attribute and key != display:
            self.personal_keys += 1
        rule: str | None = self.policy.key_decision(item.key) if item.attribute else None
        if rule is None and item.attribute and self.policy.is_sensitive_field(_last(item.key)):
            rule = "field"  # replaced as a whole at export because of its name
        stats = LocationStats(rule=rule, pattern=pattern if item.source in _KEYED else None)
        self.locations[location] = stats
        return stats

    def _group(self, groups: dict[str, GroupStats], name: str) -> GroupStats:
        label = self._safe(name)
        group = groups.get(label)
        if group is None:
            label = label if len(groups) < _MAX_GROUPS else _OTHER_GROUP
            group = groups.setdefault(label, GroupStats())
        return group

    def _safe(self, text: str) -> str:
        """Redacted form of a name taken from the data (key, service, event)."""
        cached = self._texts.get(text)
        if cached is None:
            try:
                cached = self._engine.redact_text(text)
            except Exception:
                cached = "[QUARANTINED]"
            if len(self._texts) >= _TEXT_CACHE:
                self._texts.clear()
            self._texts[text] = cached
        return cached

    def _sample(self, redacted: Any, counts: Counter[str]) -> None:
        if not self._examples_limit or not isinstance(redacted, str):
            return
        for entity in counts:
            examples = self.examples.setdefault(entity, [])
            if len(examples) >= self._examples_limit:
                continue
            start = redacted.find(f"[{entity}")
            if start < 0:
                continue
            end = redacted.find("]", start) + 1
            left, right = max(0, start - _WINDOW), min(len(redacted), end + _WINDOW)
            snippet = " ".join(redacted[left:right].split())
            if _PLACEHOLDER.fullmatch(snippet):
                continue  # a bare placeholder shows nothing useful
            snippet = ("... " if left else "") + snippet + (" ..." if right < len(redacted) else "")
            if snippet not in examples:
                examples.append(snippet)

    def _action(self, entity: str) -> str:
        if entity == E.REDACTED:
            return "replace"
        return self.policy.rule(entity).action.value

    def _warnings(
        self,
        ranked: list[tuple[Location, LocationStats]],
        suggestions: dict[Location, str | None],
    ) -> list[dict[str, str]]:
        warnings: list[dict[str, str]] = []

        def warn(code: str, message: str) -> None:
            warnings.append({"code": code, "message": message})

        for loc, stats in ranked:
            if stats.rule == "allow":
                types = ", ".join(sorted(stats.findings))
                fix = "the proposed policy masks it" if suggestions[loc] else "rename this key"
                warn(
                    "allowed_key_exposes",
                    f"keys.allow exports '{loc.key}' unchanged, but {stats.affected} value(s) "
                    f"held {types}: {fix}.",
                )
        for entity, count in sorted(self.findings.items()):
            if entity in E.BUILTIN and self.policy.rule(entity).action is Action.KEEP:
                warn(
                    "entity_kept",
                    f"{entity} is kept by the policy (action keep): "
                    f"{count} finding(s) are exported in clear.",
                )
        if self.personal_keys:
            warn(
                "personal_keys",
                f"{self.personal_keys} attribute name(s) contain personal data (shown redacted): "
                "names are exported unchanged, rename these attributes.",
            )
        messages = {
            "too_large": "value(s) longer than max_chars were not analysed: "
            "they are replaced entirely at export",
            "binary": "binary value(s) were not analysed: they are replaced entirely at export",
            "errors": "value(s) could not be analysed (detector error): "
            "they are quarantined at export",
            "unreadable": "line(s) were not valid JSON: they were analysed as text",
        }
        for name, message in messages.items():
            if self.skipped[name]:
                warn(name, f"{self.skipped[name]} {message}.")
        if any(loc.key == _OTHER_KEYS for loc, _ in ranked):
            warn(
                "many_locations",
                f"More than {_MAX_LOCATIONS} distinct keys: the rest are grouped as "
                f"'{_OTHER_KEYS}'.",
            )
        return warnings


def propose_policy(
    preset: str, *, mask: list[str], hash_: list[str], records: int, generated: str
) -> str:
    """A policy file (TOML) that adds key rules for the leaks an audit found."""
    lines = [
        f"# Policy proposed by caviard audit {__version__} on {generated}, "
        f"from {records} record(s).",
        "# Review it before use: the sample may not cover every case.",
        "# Lists add to the preset: merge them into your own policy file if you have one.",
        "version = 1",
        f"preset = {_toml(preset)}",
    ]
    mask, hash_ = sorted(set(mask)), sorted(set(hash_))
    if not mask and not hash_:
        lines.append("# No key rule needed: the detectors cover every finding of this sample.")
        return "\n".join(lines) + "\n"
    lines += ["", "[keys]"]
    if mask:
        lines += [
            "# Whole identifiers, or allowed keys that exposed personal data:",
            "# replaced as a whole (mask wins over allow).",
            "mask = [",
            *(f"    {_toml(pattern)}," for pattern in mask),
            "]",
        ]
    if hash_:
        lines += [
            "# Whole identifiers kept correlatable: the same value gives the same token.",
            "# Needs a pseudonym key: set CAVIARD_HMAC_KEY (see `caviard keygen`).",
            "hash = [",
            *(f"    {_toml(pattern)}," for pattern in hash_),
            "]",
        ]
    return "\n".join(lines) + "\n"


def _suggestion(stats: LocationStats) -> str | None:
    """Key rule to propose for a location, if any."""
    if stats.pattern is None or not stats.affected or stats.rule in _COVERED:
        return None
    whole = stats.whole >= _WHOLE_SHARE * stats.affected
    if not whole and stats.rule != "allow":
        return None  # free text: the detectors already cover it
    dominant = stats.findings.most_common(1)[0][0]
    return "hash" if whole and dominant in _CORRELATED else "mask"


def _analysis_policy(policy: Policy) -> Policy:
    """The audited policy without key rules, every detector masking: count, never hash."""
    entities = {
        name: EntityRule(Action.MASK, rule.min_score) for name, rule in policy.entities.items()
    }
    return policy.replace(
        entities=entities,
        default_action=Action.MASK,
        allow_keys=(),
        mask_keys=(),
        hash_keys=(),
        drop_keys=(),
    )


def _normalise(key: str) -> tuple[str, str]:
    """Display form and glob of a key: numeric segments (list indexes) become ``*``."""
    parts = key.split(".")
    display = ".".join("*" if _index(part) else part for part in parts)
    pattern = ".".join("*" if _index(part) else _GLOB_CHARS.sub(r"[\1]", part) for part in parts)
    return display, pattern


def _index(part: str) -> bool:
    return part.isascii() and part.isdigit()


def _last(key: str) -> str:
    return key.rsplit(".", 1)[-1]


def _groups(groups: dict[str, GroupStats]) -> list[dict[str, Any]]:
    ranked = sorted(groups.items(), key=lambda item: (-item[1].findings, item[0]))
    return [
        {"name": name, "records": g.records, "affected": g.affected, "findings": g.findings}
        for name, g in ranked[:_MAX_ROWS]
    ]


def _toml(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)  # JSON strings are valid TOML basic strings
