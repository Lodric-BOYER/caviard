"""Redaction engine for texts and structured values (span attributes, JSON)."""

from __future__ import annotations

import ast
import bisect
import functools
import json
import re
import threading
import unicodedata
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence, Sized
from typing import Any

from caviard.core import entities as E
from caviard.core.detectors import (
    Detector,
    Finding,
    MatchBudget,
    TooManyMatches,
    builtin_detectors,
    digit_count,
    load_plugin_detectors,
)
from caviard.core.errors import CaviardError, warn
from caviard.core.policy import Action, Policy, normalize_field
from caviard.core.pseudonym import Pseudonymizer, SecretKey, decode_key, resolve_key

__all__ = ["RedactionStats", "Redactor"]

_MAX_PASSES = 3
_MAX_NESTING = 64
# Regular expression matches allowed in one text, over all detectors: beyond, the text
# is replaced whole. A trace with that many identifiers is not worth reading.
_MAX_MATCHES = 10_000
_MAX_EMBEDDED = 256  # objects looked for inside one text (a log message, an error)
_MAX_EMBEDDED_FAILURES = 32  # of which failed attempts, which may read far ahead
_MAX_LITERAL = 65_536  # characters of one Python dictionary written in a text
# What matters to find the end of a Python literal: brackets, and quoted strings, whose
# content is skipped.
_LITERAL_TOKEN = re.compile(r"[{}\[\]()]|'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"")
_CLOSING = {"}": "{", "]": "[", ")": "("}
# Where an object quoted in a text may start: "{" before a key or "}" (JSON objects and
# Python dictionaries), not the braces of code blocks.
_OBJECT_START = re.compile(r"\{(?=\s*[\"'}])")

# Values written after field names in a text: JSON cut short, Python reprs holding
# objects (dataclasses, pydantic), logfmt, query strings and form bodies, YAML. A field
# is a name (the last segment of a dotted path, or of a bracketed one: user[password],
# user%5Bpassword%5D), maybe quoted, maybe followed by spaces (aligned columns), then
# "=", "=>" or ":" (not "://") and a value on the same line. The values of names that
# are not sensitive are read on, as they may hold fields too (url=...?token=...).
_FIELD = re.compile(
    r"(?:(?<=%5[Bb])|(?<![\w\-]))([A-Za-z_][\w\-]{0,63}+)(?:\]|%5[Dd])?[\"']?[ \t]{0,16}+"
    r"(?:=(?!=)(?=>?[ \t]{0,16}\S)|:(?!//)(?=[ \t]{0,16}\S))"
)
# What a field looks like from its start, to tell where a value ends.
_FIELD_AHEAD = (
    r"[\"']?[A-Za-z_][\w.\-]{0,63}(?:(?:\[|%5[Bb])[\w.\-]{0,63}(?:\]|%5[Dd])){0,8}[\"']?"
    r"[ \t]{0,16}(?:=(?!=)|:(?!//))"
)
_NEW_FIELD = re.compile(r"[ \t]*" + _FIELD_AHEAD)
_BLANKS = re.compile(r"[ \t*]{0,16}")  # spaces, and Markdown emphasis ("**Nom :** ...")
_QUOTE_STOP = re.compile(r"[\"'\\\n]")
_CALL = re.compile(r"[A-Za-z_][\w.]{0,63}(?=\()")  # Address(...), SecretStr('...')
_MAX_VALUE = 4_096  # characters of a value in quotes or brackets
_MAX_BARE = 512  # characters of a value without quotes or brackets
_LINE_BREAK = re.compile(r"[\r\n]")
# Where a bare value may end: at the line end, at a closing bracket that nothing
# continues ("Customer(name=...)"; it ends the value only when the value did not open
# it), or before the next field.
_BARE_END = re.compile(
    r"[\r\n]|[)\]}](?=[\s\"'&,;)\]}.]|$)"
    r"|(?:[,;&|][ \t]*+|(?<![ \t])[ \t]++)(?=" + _FIELD_AHEAD + ")"
)
# Bare values that hold no data: flags, nulls and type annotations without a default
# ("email: str", "phone: str | None"), matched whole.
_TYPE_NAME = (
    r"(?:str|int|float|bool|bytes|string|number|boolean|any|object|optional|list|dict"
    r"|tuple|set|secretstr|emailstr|none|null|undefined)(?:\[[\w\[\], |.]{0,64}\])?"
)
_NOT_DATA = re.compile(
    rf"(?i)(?:true|false|null|none|nil|undefined|{_TYPE_NAME}(?:[ \t]*\|[ \t]*{_TYPE_NAME}){{0,4}})"
)
# Values read to the end of their line: a cookie header holds many name=value pairs.
_WHOLE_LINE = ("cookie",)

# Characters that hide an identifier from the patterns, looked for before detection:
# compatibility forms of ASCII characters (fullwidth digits, ligatures, no-break spaces,
# superscripts), dashes, invisible format characters (zero-width space, soft hyphen,
# bidirectional marks) and combining accents written apart from their letter. Patterns
# run on a normalised view of the text; findings are mapped back to the original.
_COMBINING_RANGES: tuple[tuple[int, int], ...] = (
    (0x0300, 0x036F),
    (0x1AB0, 0x1AFF),
    (0x1DC0, 0x1DFF),
    (0x20D0, 0x20FF),
    (0xFE20, 0xFE2F),
)
_DISGUISED_RANGES: tuple[tuple[int, int], ...] = (
    (0x00A0, 0x00A0),
    (0x00AA, 0x00AA),
    (0x00AD, 0x00AD),
    (0x00B2, 0x00B3),
    (0x00B9, 0x00BA),
    (0x00BC, 0x00BE),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x2000, 0x2015),
    (0x2024, 0x2026),
    (0x202A, 0x202F),
    (0x205F, 0x209F),
    (0x2100, 0x218F),
    (0x2212, 0x2212),
    (0x2460, 0x24FF),
    (0x3000, 0x3000),
    (0xFB00, 0xFB06),
    (0xFE50, 0xFE6F),
    (0xFEFF, 0xFEFF),
    (0xFF00, 0xFFEF),
    (0xFFF9, 0xFFFB),
    (0x1D400, 0x1D7FF),
    (0x1F100, 0x1F1FF),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
)
_DASHES = frozenset(map(chr, (0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212)))
_DASHES |= frozenset(map(chr, (0xFE58, 0xFE63, 0xFF0D)))
_INT_LIMIT = 100_000_000  # integers with fewer than 9 digits cannot hold an identifier
_MAX_CLEAN_KEY = 128  # mapping keys up to this length are remembered when clean
_CLEAN_KEYS = 4_096  # how many
_ENTITY_NAME = re.compile(r"[A-Z][A-Z_]{1,31}")
# Placeholders written by caviard. They are never analysed again (idempotence).
_PLACEHOLDER = re.compile(r"\[([A-Z][A-Z_]{1,31})(?::(?:[a-z2-7]{6,32}|\.\.\.[A-Za-z0-9]{1,8}))?\]")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]")
_SURROGATE = re.compile("[\ud800-\udfff]")
_REDACTED = f"[{E.REDACTED}]"
_TOO_LARGE = f"[{E.TOO_LARGE}]"
_TOO_DEEP = object()  # json.loads raised RecursionError
_NOT_JSON = object()


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
        unknown = sorted(set(self.policy.entities) - self._protected)
        if unknown:
            warn(
                f"no detector reports {', '.join(unknown)}: these [entities] rules have no "
                "effect (check the names, or install the plugin that reports them)"
            )
        self._pseudonymizer = self._prepare_pseudonymizer(pseudonym_key)
        self.stats = RedactionStats()
        # A detector runs on a text only when one of its trigger substrings occurs: one
        # compiled search per detector rather than a Python loop over the triggers.
        self._gates = tuple(
            (d, re.compile("|".join(map(re.escape, d.triggers))) if d.triggers else None)
            for d in self._detectors
        )
        self._clean_keys: dict[str, None] = {}  # short mapping keys found clean

    @property
    def detectors(self) -> tuple[Detector, ...]:
        """Active detectors (those whose action is not ``keep``)."""
        return self._detectors

    # Texts

    def findings(self, text: str, hint: str = "") -> list[Finding]:
        """Non-overlapping findings; on overlaps the highest score, then the longest, wins.

        ``hint`` is extra context, typically the attribute key or JSON field name.
        Offsets refer to ``text``, even when patterns also ran on its normalised view.
        A value after a sensitive field name that a detector finds whole keeps the
        detector's type ("email: [EMAIL:...]").
        """
        if not text:
            return []
        try:
            view = _View.of(text)
            candidates = self._detected(text, hint, MatchBudget(_MAX_MATCHES))
            if view is not None:
                # Patterns run on both: removing an invisible character joins the parts
                # of a value, but may also glue a value to the next word.
                found = self._detected(view.text, hint, MatchBudget(_MAX_MATCHES))
                candidates += [view.finding(finding) for finding in found]
            source = text if view is None else view.text
            values = list(self._field_values(source, MatchBudget(_MAX_MATCHES)))
        except TooManyMatches:
            return [Finding(E.REDACTED, 0, len(text), 1.0, "too-many-matches")]
        if view is not None:
            values = [view.finding(finding) for finding in values]
        detected = {(finding.start, finding.end) for finding in candidates}
        candidates += [value for value in values if (value.start, value.end) not in detected]
        if not candidates:
            return []
        protected = [
            match.span()
            for match in _PLACEHOLDER.finditer(source)
            if match.group(1) in self._protected
        ]
        if view is not None:
            protected = [view.span(start, end) for start, end in protected]
        candidates.sort(key=lambda f: (-f.score, -(f.end - f.start), f.start))
        return _select(candidates, protected)

    def _detected(self, text: str, hint: str, budget: MatchBudget) -> list[Finding]:
        """Findings of the detectors in ``text``; each one is skipped early when the
        text lacks its triggers, required substrings or digits."""
        lowered = text.lower()
        digits = digit_count(lowered)
        found: list[Finding] = []
        for detector, gate in self._gates:
            if gate is not None and gate.search(lowered) is None:
                continue
            if detector.min_digits > digits:
                continue
            if type(detector) is Detector:  # gated here already
                if detector.requires and not all(r in lowered for r in detector.requires):
                    continue
                matches = detector._matches(text, hint, budget)
            else:  # a subclass may filter in its own find()
                matches = detector.find(text, lowered, hint, budget)
            minimum = self._min_score.get(detector.entity, 0.0)
            found.extend(finding for finding in matches if finding.score >= minimum)
        return found

    def redact_text(self, text: str, hint: str = "") -> str:
        """Replace every finding by a placeholder. Idempotent."""
        if not text:
            return text
        if len(text) > self.policy.max_chars:
            self.stats.add(E.TOO_LARGE)
            return _TOO_LARGE
        current = text
        for _ in range(_MAX_PASSES):
            found = self.findings(current, hint)
            if not found:
                break
            current = self._apply(current, found)
        else:
            if self.findings(current, hint):
                # Each pass widens findings over the placeholders they touch; a text
                # built to need more passes is replaced whole.
                self.stats.add(E.REDACTED)
                return _REDACTED
        return self._fitted(current)

    # Structured values

    def redact_value(self, value: Any, hint: str = "") -> Any:
        """Redact a value: text (JSON-aware), number, sequence, set or mapping.

        Strings holding JSON objects or arrays are decoded, walked and encoded
        again (only when something changed). Field names listed in
        ``json.sensitive_fields`` have their whole value replaced, and mapping
        keys are redacted like values. Values of any other type (bytes, objects)
        are replaced whole.
        """
        return self._walk(value, hint, 0, 0)[0]

    def redact_key(self, key: Any) -> Any:
        """Redact a mapping key the way :meth:`redact_value` does for nested mappings."""
        return self._key(key, 0, 0)[0]

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
            elif decision == "hash":  # key rules win over field names
                result[key] = self._whole(value, pseudonymise=True)
            elif decision == "mask" or self._sensitive_name(key.rsplit(".", 1)[-1]):
                result[key] = self._whole(value, pseudonymise=False)
            else:
                result[key] = _homogeneous(self._walk(value, key, 0, 0)[0])
        return result

    # Internals

    def _field_values(self, text: str, budget: MatchBudget) -> Iterator[Finding]:
        """Values written after a sensitive field name, such as ``customer_name='...'``.

        The scan is linear: only the values found spend ``budget``.
        """
        policy = self.policy
        if not policy.sensitive_fields or ("=" not in text and ":" not in text):
            return
        # Names are looked for after the last value found: that value becomes a
        # placeholder, after which a later pass would read another name.
        position = 0
        while (field := _FIELD.search(text, position)) is not None:
            at = field.end() - 1  # the separator
            position = at + 1
            name = field.group(1)
            if not policy.is_sensitive_field(name) or self._by_placeholder(text, field.start(1)):
                continue
            whole_line = any(word in normalize_field(name) for word in _WHOLE_LINE)
            value = _field_value(text, at, whole_line=whole_line)
            if value is not None:
                budget.spend()
                yield Finding(E.REDACTED, value[0], value[1], 0.99, "field-value")
                position = max(position, value[1])

    def _by_placeholder(self, text: str, start: int) -> bool:
        """Whether the name at ``start`` is inside a placeholder, or right after one: an
        earlier pass wrote it there, and the name it cut ("jean@exemple.fr_token") is
        another one."""
        if not start:
            return False
        if text[start - 1] == "[":
            match = _PLACEHOLDER.match(text, start - 1)
            return match is not None and match.group(1) in self._protected
        if text[start - 1] == "]":
            opening = text.rfind("[", max(0, start - 72), start - 1)
            if opening != -1:
                match = _PLACEHOLDER.fullmatch(text, opening, start)
                return match is not None and match.group(1) in self._protected
        return False

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
            warn(
                f"no pseudonym key configured (set {source}): using a random key for this "
                "process, so pseudonyms will change after a restart"
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
            return f"[{entity}:{self._token(entity, _plain(value))}]"
        if rule.action is Action.PARTIAL:
            tail = _NON_ALNUM.sub("", _plain(value))[-rule.keep_last :]
            if tail:
                return f"[{entity}:...{tail}]"
        return f"[{entity}]"

    def _fitted(self, text: str) -> str:
        """``text``, or ``[TOO_LARGE]`` when placeholders made it longer than ``max_chars``
        (a second pass would replace it, which would break idempotence)."""
        if len(text) > self.policy.max_chars:
            self.stats.add(E.TOO_LARGE)
            return _TOO_LARGE
        return text

    def _encoded(self, value: Any) -> str:
        """JSON text of a redacted document, compact when the usual layout is too long."""
        text = _json_text(value)
        if len(text) > self.policy.max_chars:
            text = _json_text(value, compact=True)
        return self._fitted(text)

    def _whole(self, value: Any, *, pseudonymise: bool) -> str:
        if isinstance(value, str):
            match = _PLACEHOLDER.fullmatch(value)
            if match is not None and match.group(1) == E.REDACTED:
                return value
        self.stats.add(E.REDACTED)
        if pseudonymise:
            return f"[{E.REDACTED}:{self._token(E.REDACTED, _plain(str(value)))}]"
        return _REDACTED

    def _string(self, text: str, hint: str, depth: int) -> Any:
        if not text:
            return text
        if len(text) > self.policy.max_chars:
            self.stats.add(E.TOO_LARGE)
            return _TOO_LARGE
        decode = depth < self.policy.json_max_depth
        # Past json.max_depth, JSON is still recognised (but no longer walked) so that it
        # can be replaced: read as plain text, it would skip the field-name rules.
        start = text.lstrip()[:1]
        if (decode or depth) and start in ("{", "[", '"'):
            repeated: list[str] = []
            try:
                parsed = json.loads(text, object_pairs_hook=_pairs(repeated))
            except ValueError:
                parsed = _NOT_JSON
            except RecursionError:
                # Too deep for this interpreter (the limit varies with the Python
                # version and the stack size): fail closed for the same reason.
                parsed = _TOO_DEEP
            if parsed is _TOO_DEEP or (not decode and isinstance(parsed, dict | list)):
                self.stats.add(E.REDACTED)
                return _REDACTED
            if isinstance(parsed, dict | list):
                redacted, changed = self._walk(parsed, hint, depth + 1, 0)
                # With a repeated key, only its last value was walked: the text is encoded
                # again rather than returned with the other values in it.
                if changed or repeated:
                    return self._encoded(redacted)
                return text
            if isinstance(parsed, str):
                # A JSON string, maybe holding a JSON document (Langfuse encodes every
                # metadata value): decoded, redacted, encoded again.
                inner = self._string(parsed, hint, depth + 1)
                return self._encoded(inner) if inner != parsed else text
        if "{" in text and (decode or depth):
            embedded = self._embedded(text, hint, depth, decode)
            if embedded is not None:
                return embedded
        return self.redact_text(text, hint)

    def _embedded(self, text: str, hint: str, depth: int, decode: bool) -> str | None:
        """Walk the JSON objects inside a longer text, so that field names apply to them.

        Log messages and errors often quote a payload ("calling tool with {...}").
        Returns None when no object changed; the caller then reads the text as is.
        Only braces that open a key are tried, and a bounded number of them: past
        that, the rest is read as text, where field names still apply.
        """
        pieces: list[str] = []
        last = 0
        attempts = failures = 0
        candidate = _OBJECT_START.search(text)
        while (
            candidate is not None and attempts < _MAX_EMBEDDED and failures < _MAX_EMBEDDED_FAILURES
        ):
            attempts += 1
            index = candidate.start()
            literal = _literal_at(text, index)
            if literal is None:
                failures += 1
                candidate = _OBJECT_START.search(text, index + 1)
                continue
            found, end, render, repeated = literal
            if found is _TOO_DEEP or not decode:
                self.stats.add(E.REDACTED)
                return _REDACTED
            redacted, changed = self._walk(found, hint, depth + 1, 0)
            if changed or repeated:
                pieces.append(text[last:index])
                pieces.append(render(redacted))
                last = end
            candidate = _OBJECT_START.search(text, end)
        if not pieces:
            return None
        pieces.append(text[last:])
        return self.redact_text("".join(pieces), hint)

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

    def _float(self, value: float, hint: str) -> float | str:
        # An integral float can still carry an identifier (a phone number read as 612345678.0).
        if not value.is_integer() or -_INT_LIMIT < value < _INT_LIMIT:
            return value
        text = str(int(value))
        redacted = self.redact_text(text, hint)
        return value if redacted == text else redacted

    def _walk(self, node: Any, hint: str, depth: int, level: int) -> tuple[Any, bool]:
        """Redact a decoded JSON value or any Python value; returns it with a changed flag.

        Containers are rebuilt (tuples, sets and mappings keep their kind), and any
        other type is replaced whole: what cannot be inspected is never exported.
        """
        if level > _MAX_NESTING:
            self.stats.add(E.REDACTED)
            return _REDACTED, True
        if node is None or isinstance(node, bool):
            return node, False
        if isinstance(node, str):
            new_text = self._string(node, hint, depth)
            return new_text, new_text != node
        if isinstance(node, int):
            new_number = self._integer(node, hint)
            return new_number, new_number != node
        if isinstance(node, float):
            new_float = self._float(node, hint)
            return new_float, new_float is not node
        if isinstance(node, Mapping):
            return self._mapping(node, depth, level)
        if isinstance(node, list | tuple | set | frozenset):
            items: list[Any] = []
            changed = False
            for item in node:
                new_item, item_changed = self._walk(item, hint, depth, level + 1)
                items.append(new_item)
                changed = changed or item_changed
            if isinstance(node, list):
                return items, changed
            if isinstance(node, tuple):
                return tuple(items), changed
            return (frozenset(items) if isinstance(node, frozenset) else set(items)), changed
        self.stats.add(E.REDACTED)
        return _REDACTED, True

    def _mapping(
        self, node: Mapping[Any, Any], depth: int, level: int
    ) -> tuple[dict[Any, Any], bool]:
        result: dict[Any, Any] = {}
        changed = False
        for key, item in node.items():
            name = key if isinstance(key, str) else str(key)
            new_key, key_changed = self._key(key, depth, level)
            if new_key in result:  # original keys are unique: redaction made them collide
                new_key, key_changed = _free_key(result, str(new_key)), True
            if self._sensitive(name, item):
                if not (isinstance(item, str) and item == _REDACTED):
                    self.stats.add(E.REDACTED)
                    changed = True
                result[new_key] = _REDACTED
            else:
                result[new_key], item_changed = self._walk(item, name, depth, level + 1)
                changed = changed or item_changed
            changed = changed or key_changed
        return result, changed

    def _key(self, key: Any, depth: int, level: int) -> tuple[Any, bool]:
        # Keys hold personal data too (a mapping keyed by e-mail): redacted like values.
        # Documents repeat the same keys: short ones found clean are remembered.
        if isinstance(key, str):
            if key in self._clean_keys:
                return key, False
            new_key = self.redact_text(key)
            if new_key == key and len(key) <= _MAX_CLEAN_KEY:
                if len(self._clean_keys) >= _CLEAN_KEYS:
                    self._clean_keys.clear()
                self._clean_keys[key] = None
            return new_key, new_key != key
        return self._walk(key, "", depth, level + 1)

    def _sensitive(self, name: str, item: Any) -> bool:
        """Values under a sensitive field name are replaced whole, whatever their type."""
        if item is None or isinstance(item, bool) or (isinstance(item, Sized) and not len(item)):
            return False
        return self._sensitive_name(name)

    def _sensitive_name(self, name: str) -> bool:
        """Whether ``name`` is a sensitive field name.

        A name holding a placeholder was redacted: it is never one ("[IBAN] }" is not
        the field name "iban"), so a second pass leaves its value as the first did.
        """
        if "[" in name and any(
            match.group(1) in self._protected for match in _PLACEHOLDER.finditer(name)
        ):
            return False
        return self.policy.is_sensitive_field(name)


def _ranges(ranges: tuple[tuple[int, int], ...]) -> str:
    """Regular expression class body for code point ranges, written with escapes."""
    return "".join(rf"\U{first:08x}-\U{last:08x}" for first, last in ranges)


_DISGUISED = re.compile(f"[{_ranges(_DISGUISED_RANGES + _COMBINING_RANGES)}]")
_COMBINING_MARK = re.compile(f"[{_ranges(_COMBINING_RANGES)}]")
_MIN_UNEVEN = 10_000  # characters a text may have removed or expanded, at the least


@functools.cache
def _translations() -> tuple[dict[int, str], re.Pattern[str]]:
    """The disguised characters whose normal form is one character, as a ``str.translate``
    table (offsets are kept), and a pattern for the others: removed (invisible),
    expanded ("½") or composed with the letter before them (accents)."""
    table: dict[int, str] = {}
    uneven: list[tuple[int, int]] = []
    for first, last in _DISGUISED_RANGES:
        for code in range(first, last + 1):
            normal = _normal(chr(code))
            if len(normal) == 1:
                if normal != chr(code):
                    table[code] = normal
            else:
                uneven.append((code, code))
    pattern = re.compile(f"[{_ranges(_COMBINING_RANGES)}]+|[{_ranges(tuple(uneven))}]")
    return table, pattern


class _View:
    """A text with its disguised characters normalised, and the map back to the text.

    Pieces of the view are either aligned with the text (copied, or translated one
    character for one) or replace one character, or a letter and its combining
    accents; ``_marks`` holds where each piece starts in the view, ``_origins`` where
    it starts in the text, and ``_ends`` where a replacing piece ends in the text (-1
    for aligned pieces).
    """

    __slots__ = ("_ends", "_marks", "_origins", "text")

    def __init__(self, text: str, marks: list[int], origins: list[int], ends: list[int]) -> None:
        self.text = text
        self._marks = marks
        self._origins = origins
        self._ends = ends

    @classmethod
    def of(cls, text: str) -> _View | None:
        """The normalised view of ``text``; None when nothing needs normalising.

        Raises TooManyMatches when a large part of a long text would be removed or
        expanded: such a text is replaced whole.
        """
        if text.isascii() or _DISGUISED.search(text) is None:
            return None
        table, uneven = _translations()
        if uneven.search(text) is None:
            aligned = text.translate(table)
            return None if aligned == text else cls(aligned, [0], [0], [-1])
        limit = max(_MIN_UNEVEN, len(text) // 4)
        pieces: list[str] = []
        marks: list[int] = []
        origins: list[int] = []
        ends: list[int] = []
        size = last = changes = 0
        for match in uneven.finditer(text):
            start = match.start()
            if start > last and _COMBINING_MARK.match(text, start):
                start -= 1  # the letter the accents belong to
            end = match.end()
            piece = text[start:end]
            replacement = _normal(piece) if len(piece) <= 17 else piece
            if replacement == piece:
                continue
            changes += 1
            if changes > limit:
                raise TooManyMatches
            if start > last:
                marks.append(size)
                origins.append(last)
                ends.append(-1)
                pieces.append(text[last:start].translate(table))
                size += start - last
            if replacement:
                marks.append(size)
                origins.append(start)
                ends.append(end)
                pieces.append(replacement)
                size += len(replacement)
            last = end
        if not changes:
            aligned = text.translate(table)
            return None if aligned == text else cls(aligned, [0], [0], [-1])
        if last < len(text):
            marks.append(size)
            origins.append(last)
            ends.append(-1)
            pieces.append(text[last:].translate(table))
        return cls("".join(pieces), marks, origins, ends)

    def span(self, start: int, end: int) -> tuple[int, int]:
        """Text offsets of the view characters ``start`` to ``end`` (excluded)."""
        first = bisect.bisect_right(self._marks, start) - 1
        if self._ends[first] < 0:
            text_start = self._origins[first] + start - self._marks[first]
        else:
            text_start = self._origins[first]
        last = bisect.bisect_right(self._marks, end - 1) - 1
        if self._ends[last] < 0:
            text_end = self._origins[last] + end - self._marks[last]
        else:
            text_end = self._ends[last]
        return text_start, text_end

    def finding(self, finding: Finding) -> Finding:
        start, end = self.span(finding.start, finding.end)
        return Finding(finding.entity, start, end, finding.score, finding.detector)


def _plain(value: str) -> str:
    """``value`` with its disguised characters normalised: a fullwidth or zero-width
    variant of a value gets the same pseudonym and the same last characters."""
    try:
        view = _View.of(value)
    except TooManyMatches:
        return value
    return value if view is None else view.text


@functools.lru_cache(maxsize=4096)
def _normal(piece: str) -> str:
    """Normal form of a disguised character, or of a letter and its combining accents
    (at most 16)."""
    if piece in _DASHES:
        return "-"
    if unicodedata.category(piece[0]) == "Cf":
        return ""  # invisible: zero-width space, soft hyphen, bidirectional mark
    return unicodedata.normalize("NFKC", piece)


def _field_value(text: str, at: int, *, whole_line: bool = False) -> tuple[int, int] | None:
    """Span of the value written after the separator at ``at``; None when there is none.

    A quoted value stops at its closing quote, a value in brackets (``[...]``,
    ``Address(...)``) at its closing bracket, or the line end when that one is too far,
    and a bare value at the next field, a closing bracket it did not open or the line
    end. Unclear cases lean toward redacting more.
    """
    start = at + 2 if text.startswith("=>", at) else at + 1
    blanks = _BLANKS.match(text, start)
    start = blanks.end() if blanks is not None else start
    if start >= len(text):
        return None
    if whole_line:
        return start, _line_end(text, start)
    if text[start] in "\"'":
        return _quoted_value(text, start)
    call = _CALL.match(text, start)
    opening = call.end() if call is not None else start
    if text[opening : opening + 1] in ("(", "[", "{"):
        end = _literal_end(text, opening, _MAX_VALUE)
        if end == -1:
            return start, _line_end(text, start)
        # A value may go on after its brackets: "(+33) 6 12 34 56 78", "[EMAIL]Camille".
        return start, max(end, _bare_end(text, end, start))
    return _bare_value(text, start)


def _quoted_value(text: str, start: int) -> tuple[int, int] | None:
    """The text between the quote at ``start`` and its closing quote.

    In single quotes, a quote between two letters is an apostrophe ("O'Neil"). A quote
    left open (cut off) stops at the end of its line, and so does a quote whose next
    line starts another field: it would otherwise pair with that field's quote.
    """
    quote = text[start]
    limit = min(len(text), start + 1 + _MAX_VALUE)
    position = start + 1
    line_end = -1
    while (stop := _QUOTE_STOP.search(text, position, limit)) is not None:
        index = stop.start()
        char = text[index]
        position = index + 1
        if char == "\\":
            position += 1  # an escaped character
        elif char == "\n":
            if line_end == -1:
                line_end = index
            if _NEW_FIELD.match(text, index + 1):
                break
        elif char == quote and not (quote == "'" and _apostrophe(text, index)):
            return (start + 1, index) if index > start + 1 else None
    end = line_end if line_end != -1 else limit
    return (start + 1, end) if end > start + 1 else None


def _apostrophe(text: str, index: int) -> bool:
    """Whether the single quote at ``index`` is an apostrophe: between two letters, and
    not followed by another field ("name='x'plan='y'")."""
    return (
        index > 0
        and index + 1 < len(text)
        and text[index - 1].isalpha()
        and text[index + 1].isalpha()
        and _NEW_FIELD.match(text, index + 1) is None
    )


def _line_end(text: str, start: int) -> int:
    limit = min(len(text), start + _MAX_VALUE)
    match = _LINE_BREAK.search(text, start, limit)
    return match.start() if match is not None else limit


def _bare_end(text: str, start: int, origin: int) -> int:
    """Where a bare value read from ``start`` ends, its final punctuation left out;
    ``origin`` is where the whole value starts. A closing bracket ends the value only
    when the value did not open it: "12 rue des Lilas (bâtiment B) 69001 Lyon" is one
    value, and so is a placeholder glued to a value ("[SECRET]hunter2")."""
    limit = min(len(text), start + _MAX_BARE)
    position = start
    while (stop := _BARE_END.search(text, position, limit)) is not None:
        end = stop.start()
        if text[end] not in ")]}" or _depth(text, origin, end) <= 0:
            break
        position = end + 1
    end = stop.start() if stop is not None else limit
    while end > start and text[end - 1] in " \t,;.":
        end -= 1  # the punctuation that ends a sentence or a list item
    return end


def _depth(text: str, start: int, end: int) -> int:
    """Brackets opened and not closed in ``text[start:end]``."""
    return sum(text.count(char, start, end) for char in "([{") - sum(
        text.count(char, start, end) for char in ")]}"
    )


def _bare_value(text: str, start: int) -> tuple[int, int] | None:
    end = _bare_end(text, start, start)
    if end > start and text[end - 1] in "\"'" and text.count(text[end - 1], start, end) == 1:
        end -= 1  # the quote that closes an enclosing text: msg="password=..."
    if end <= start or _NOT_DATA.fullmatch(text, start, end):
        return None
    return start, end


def _literal_at(text: str, index: int) -> tuple[Any, int, Any, bool] | None:
    """The JSON object or Python dictionary starting at ``index``: the value, its end,
    a renderer and whether a key was repeated (only its last value is kept).

    Python dictionaries come from messages such as ``f"args {args}"``; they are read
    with ``ast.literal_eval``, which evaluates literals only, never code.
    """
    repeated: list[str] = []
    try:
        found, end = json.JSONDecoder(object_pairs_hook=_pairs(repeated)).raw_decode(text, index)
    except ValueError:
        pass
    except RecursionError:
        return _TOO_DEEP, len(text), None, False
    else:
        return found, end, _json_text, bool(repeated)
    end = _literal_end(text, index)
    if end == -1:
        return None
    try:
        tree = ast.parse(text[index:end], mode="eval")
        found = ast.literal_eval(tree)
        if not isinstance(found, dict):
            return None
        return found, end, repr, _repeats_keys(tree)
    except (ValueError, TypeError, SyntaxError, MemoryError):
        return None
    except RecursionError:
        return _TOO_DEEP, end, None, False


def _pairs(repeated: list[str]) -> Any:
    """A json ``object_pairs_hook`` that notes repeated keys in ``repeated``."""

    def build(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = dict(pairs)
        if len(result) != len(pairs):
            repeated.append("")
        return result

    return build


def _repeats_keys(tree: ast.AST) -> bool:
    """True when a dictionary display of the literal repeats a key."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys = [ast.literal_eval(key) for key in node.keys if key is not None]
            if len(set(keys)) != len(keys):
                return True
    return False


def _literal_end(text: str, index: int, limit: int = _MAX_LITERAL) -> int:
    """Index just past the bracket closing the one at ``index``; -1 if not found soon."""
    stack: list[str] = []
    for match in _LITERAL_TOKEN.finditer(text, index, min(len(text), index + limit)):
        part = match.group()
        if part in ("{", "[", "("):
            stack.append(part)
            if len(stack) > _MAX_NESTING:
                return -1
        elif part in _CLOSING:
            if not stack or stack.pop() != _CLOSING[part]:
                return -1
            if not stack:
                return match.end()
    return -1


def _json_text(value: Any, *, compact: bool = False) -> str:
    """JSON text of ``value``. Non-ASCII characters stay readable, but a lone surrogate
    (decoded from a ``\\ud800`` escape) stays escaped: exporters cannot encode it."""
    separators = (",", ":") if compact else None
    text = json.dumps(value, ensure_ascii=False, separators=separators)
    if _SURROGATE.search(text) is not None:
        return json.dumps(value, separators=separators)
    return text


def _homogeneous(value: Any) -> Any:
    """OpenTelemetry attribute sequences hold a single type: when a text appears, all are."""
    if isinstance(value, list | tuple) and any(isinstance(item, str) for item in value):
        items = [_as_text(item) for item in value]
        return tuple(items) if isinstance(value, tuple) else items
    return value


def _as_text(item: Any) -> str:
    if isinstance(item, str):
        return item
    return "" if item is None else str(item)


def _free_key(result: Mapping[Any, Any], key: str) -> str:
    """Two keys redacted to the same text keep both values: ``[IBAN]``, ``[IBAN]#2``..."""
    index = 2
    while f"{key}#{index}" in result:
        index += 1
    return f"{key}#{index}"


def _select(candidates: list[Finding], protected: list[tuple[int, int]]) -> list[Finding]:
    """Keep the best non-overlapping findings; ``candidates`` come best first.

    ``protected`` lists the placeholders already in the text, in order. A finding inside
    one is dropped, so a second pass changes nothing; a finding that overlaps one is
    widened to cover it whole, so a placeholder glued to a value ("[SECRET]hunter2")
    never shields that value.
    """
    marks = [start for start, _ in protected]
    starts: list[int] = []
    ends: list[int] = []
    chosen: list[Finding] = []
    for finding in candidates:
        start, end = finding.start, finding.end
        first = bisect.bisect_right(marks, start) - 1
        if first >= 0 and protected[first][1] > start:
            if end <= protected[first][1]:
                continue
            start = protected[first][0]
        last = bisect.bisect_left(marks, end) - 1
        if last >= 0 and protected[last][1] > end:
            end = protected[last][1]
        index = bisect.bisect_right(starts, start)
        if (index and ends[index - 1] > start) or (index < len(starts) and starts[index] < end):
            continue
        starts.insert(index, start)
        ends.insert(index, end)
        if (start, end) != (finding.start, finding.end):
            finding = Finding(finding.entity, start, end, finding.score, finding.detector)
        chosen.append(finding)
    chosen.sort(key=lambda finding: finding.start)
    return chosen
