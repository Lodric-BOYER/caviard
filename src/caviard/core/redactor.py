"""Redaction engine for texts and structured values (span attributes, JSON)."""

from __future__ import annotations

import bisect
import json
import re
import threading
import warnings
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from caviard.core import entities as E
from caviard.core.detectors import Detector, Finding, builtin_detectors, load_plugin_detectors
from caviard.core.errors import CaviardError, CaviardWarning, RedactionError
from caviard.core.policy import Action, Policy
from caviard.core.pseudonym import Pseudonymizer, SecretKey, decode_key, resolve_key

__all__ = ["RedactionStats", "Redactor"]

_MAX_PASSES = 3
_MAX_NESTING = 64
_INT_LIMIT = 100_000_000  # integers with fewer than 9 digits cannot hold an identifier
_ENTITY_NAME = re.compile(r"[A-Z][A-Z_]{1,31}")
# Placeholders written by caviard. They are never analysed again (idempotence).
_PLACEHOLDER = re.compile(r"\[([A-Z][A-Z_]{1,31})(?::(?:[a-z2-7]{6,32}|\.\.\.[A-Za-z0-9]{1,8}))?\]")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")
_REDACTED = f"[{E.REDACTED}]"


class RedactionStats:
    """Thread-safe counters per entity. Only counts are kept, never values."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()

    def add(self, entity: str, count: int = 1) -> None:
        with self._lock:
            self._counts[entity] += count

    def update(self, counts: Mapping[str, int]) -> None:
        with self._lock:
            self._counts.update(counts)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()


class Redactor:
    """Detects and replaces personal data and secrets according to a policy.

    A Redactor is thread-safe and meant to be long-lived: detectors, key rules
    and the pseudonym key are prepared once, at construction.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        detectors: Sequence[Detector] | None = None,
        extra_detectors: Iterable[Detector] = (),
        pseudonym_key: bytes | str | SecretKey | None = None,
    ) -> None:
        self.policy = policy if policy is not None else Policy.default()
        if detectors is None:
            available = list(builtin_detectors())
            if self.policy.plugins:
                available.extend(load_plugin_detectors())
        else:
            available = list(detectors)
        available.extend(extra_detectors)
        for detector in available:
            if not _ENTITY_NAME.fullmatch(detector.entity):
                raise CaviardError(f"detector {detector.name!r} has an invalid entity name")
        rules = self.policy
        self._detectors = tuple(
            d for d in available if rules.rule(d.entity).action is not Action.KEEP
        )
        self._min_score = {d.entity: rules.rule(d.entity).min_score for d in self._detectors}
        self._protected = frozenset(d.entity for d in available) | frozenset(E.SPECIAL)
        self._pseudonymizer = self._prepare_pseudonymizer(pseudonym_key)
        self.stats = RedactionStats()

    @property
    def detectors(self) -> tuple[Detector, ...]:
        """Active detectors (those whose action is not ``keep``)."""
        return self._detectors

    # Texts

    def findings(self, text: str, hint: str = "") -> list[Finding]:
        """Non-overlapping findings; on overlaps the highest score, then the longest, wins.

        ``hint`` is extra context, typically the attribute key or JSON field name.
        """
        if not text:
            return []
        lowered = text.lower()
        candidates = [
            finding
            for detector in self._detectors
            for finding in detector.find(text, lowered, hint)
            if finding.score >= self._min_score.get(finding.entity, 0.0)
        ]
        if not candidates:
            return []
        protected = [
            match.span()
            for match in _PLACEHOLDER.finditer(text)
            if match.group(1) in self._protected
        ]
        candidates.sort(key=lambda f: (-f.score, -(f.end - f.start), f.start))
        return _select(candidates, protected)

    def redact_text(self, text: str, hint: str = "") -> str:
        """Replace every finding by a placeholder. Idempotent."""
        if not text:
            return text
        if len(text) > self.policy.max_chars:
            self.stats.add(E.TOO_LARGE)
            return f"[{E.TOO_LARGE}]"
        current = text
        for _ in range(_MAX_PASSES):
            found = self.findings(current, hint)
            if not found:
                return current
            current = self._apply(current, found)
        if self.findings(current, hint):
            raise RedactionError("redaction did not converge")
        return current

    # Structured values

    def redact_value(self, value: Any, hint: str = "") -> Any:
        """Redact a value: text (JSON-aware), number, sequence or mapping.

        Strings holding JSON objects or arrays are decoded, walked and encoded
        again (only when something changed). Field names listed in
        ``json.sensitive_fields`` have their whole value replaced.
        """
        return self._value(value, hint, 0)

    def redact_attributes(self, attributes: Mapping[str, Any] | None) -> dict[str, Any]:
        """Redact OpenTelemetry-style attributes, applying the key rules first."""
        result: dict[str, Any] = {}
        if not attributes:
            return result
        for key, value in attributes.items():
            decision = self.policy.key_decision(key)
            if decision == "allow":
                result[key] = value
            elif decision == "drop":
                self.stats.add(E.DROPPED)
            elif value is None or isinstance(value, bool):
                result[key] = value
            elif decision == "mask" or self.policy.is_sensitive_field(key.rsplit(".", 1)[-1]):
                result[key] = self._whole(value, pseudonymise=False)
            elif decision == "hash":
                result[key] = self._whole(value, pseudonymise=True)
            else:
                result[key] = self._value(value, key, 0)
        return result

    # Internals

    def _prepare_pseudonymizer(self, key: bytes | str | SecretKey | None) -> Pseudonymizer | None:
        policy = self.policy
        uses_hash = (
            bool(policy.hash_keys)
            or policy.default_action is Action.HASH
            or any(rule.action is Action.HASH for rule in policy.entities.values())
        )
        if isinstance(key, SecretKey):
            secret: SecretKey | None = key
        elif isinstance(key, bytes):
            secret = SecretKey(key)
        elif isinstance(key, str):
            secret = SecretKey(decode_key(key))
        else:
            secret = resolve_key(policy.key_env, policy.key_file) if uses_hash else None
        if secret is None:
            if not uses_hash:
                return None
            source = policy.key_env or "pseudonym.key_file"
            warnings.warn(
                f"no pseudonym key configured (set {source}): using a random key for this "
                "process, so pseudonyms will change after a restart",
                CaviardWarning,
                stacklevel=3,
            )
            secret = SecretKey.generate()
        return Pseudonymizer(secret, policy.pseudonym_length)

    def _token(self, entity: str, value: str) -> str:
        if self._pseudonymizer is None:  # a custom detector may use hash in a mask-only policy
            self._pseudonymizer = Pseudonymizer(SecretKey.generate(), self.policy.pseudonym_length)
        return self._pseudonymizer.token(entity, value)

    def _apply(self, text: str, found: list[Finding]) -> str:
        parts: list[str] = []
        last = 0
        for finding in found:
            parts.append(text[last : finding.start])
            parts.append(self._replacement(finding.entity, text[finding.start : finding.end]))
            last = finding.end
        parts.append(text[last:])
        self.stats.update(Counter(finding.entity for finding in found))
        return "".join(parts)

    def _replacement(self, entity: str, value: str) -> str:
        rule = self.policy.rule(entity)
        if rule.action is Action.HASH:
            return f"[{entity}:{self._token(entity, value)}]"
        if rule.action is Action.PARTIAL:
            tail = _NON_ALNUM.sub("", value)[-rule.keep_last :]
            if tail:
                return f"[{entity}:...{tail}]"
        return f"[{entity}]"

    def _whole(self, value: Any, *, pseudonymise: bool) -> str:
        if isinstance(value, str):
            match = _PLACEHOLDER.fullmatch(value)
            if match is not None and match.group(1) == E.REDACTED:
                return value
        self.stats.add(E.REDACTED)
        if pseudonymise:
            return f"[{E.REDACTED}:{self._token(E.REDACTED, str(value))}]"
        return _REDACTED

    def _value(self, value: Any, hint: str, depth: int) -> Any:
        if value is None or isinstance(value, bool | float):
            return value
        if isinstance(value, str):
            return self._string(value, hint, depth)
        if isinstance(value, int):
            return self._integer(value, hint)
        if isinstance(value, Mapping):
            return self._walk(dict(value), hint, depth, 0)[0]
        if isinstance(value, list | tuple):
            items = [self._value(item, hint, depth) for item in value]
            if any(isinstance(item, str) for item in items):
                # OpenTelemetry sequences must be homogeneous.
                items = [_as_text(item) for item in items]
            return tuple(items) if isinstance(value, tuple) else items
        self.stats.add(E.REDACTED)
        return _REDACTED

    def _string(self, text: str, hint: str, depth: int) -> Any:
        if not text:
            return text
        if len(text) > self.policy.max_chars:
            self.stats.add(E.TOO_LARGE)
            return f"[{E.TOO_LARGE}]"
        if depth < self.policy.json_max_depth and text.lstrip()[:1] in ("{", "["):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            except RecursionError:
                # Too deep for this interpreter (the limit varies with the Python
                # version and the stack size): the text fallback would skip the
                # field-name rules, so fail closed instead.
                self.stats.add(E.REDACTED)
                return _REDACTED
            if isinstance(parsed, dict | list):
                redacted, changed = self._walk(parsed, hint, depth + 1, 0)
                return json.dumps(redacted, ensure_ascii=False) if changed else text
        return self.redact_text(text, hint)

    def _integer(self, value: int, hint: str) -> int | str:
        if -_INT_LIMIT < value < _INT_LIMIT:
            return value
        try:
            text = str(value)
        except ValueError:  # beyond sys.get_int_max_str_digits()
            self.stats.add(E.REDACTED)
            return _REDACTED
        redacted = self.redact_text(text, hint)
        return value if redacted == text else redacted

    def _walk(self, node: Any, hint: str, depth: int, level: int) -> tuple[Any, bool]:
        if level > _MAX_NESTING:
            self.stats.add(E.REDACTED)
            return _REDACTED, True
        if isinstance(node, dict):
            result: dict[Any, Any] = {}
            changed = False
            for key, item in node.items():
                name = str(key)
                if self._sensitive_scalar(name, item):
                    if item != _REDACTED:
                        self.stats.add(E.REDACTED)
                        changed = True
                    result[key] = _REDACTED
                    continue
                result[key], item_changed = self._walk(item, name, depth, level + 1)
                changed = changed or item_changed
            return result, changed
        if isinstance(node, list):
            items: list[Any] = []
            changed = False
            for item in node:
                new_item, item_changed = self._walk(item, hint, depth, level + 1)
                items.append(new_item)
                changed = changed or item_changed
            return items, changed
        if isinstance(node, str):
            new_text = self._string(node, hint, depth)
            return new_text, new_text != node
        if isinstance(node, int) and not isinstance(node, bool):
            new_number = self._integer(node, hint)
            return new_number, new_number != node
        return node, False

    def _sensitive_scalar(self, name: str, item: Any) -> bool:
        if isinstance(item, bool) or not isinstance(item, str | int | float) or item == "":
            return False
        return self.policy.is_sensitive_field(name)


def _as_text(item: Any) -> str:
    if isinstance(item, str):
        return item
    return "" if item is None else str(item)


def _select(candidates: list[Finding], protected: list[tuple[int, int]]) -> list[Finding]:
    """Keep the best non-overlapping findings; ``candidates`` come best first."""
    starts: list[int] = []
    ends: list[int] = []

    def place(start: int, end: int) -> bool:
        index = bisect.bisect_right(starts, start)
        if index and ends[index - 1] > start:
            return False
        if index < len(starts) and starts[index] < end:
            return False
        starts.insert(index, start)
        ends.insert(index, end)
        return True

    for start, end in protected:
        place(start, end)
    chosen = [finding for finding in candidates if place(finding.start, finding.end)]
    chosen.sort(key=lambda finding: finding.start)
    return chosen
