"""Built-in detectors.

A detector combines a bounded regular expression, an optional validation
function (checksum, address parser) and optional context words. Detectors
whose validation is weak (Luhn alone accepts one random number in ten)
require a context word near the match.
"""

from __future__ import annotations

import ipaddress
import re
import string
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from importlib import metadata

from caviard.core import checksums
from caviard.core import entities as E
from caviard.core.errors import CaviardError

__all__ = [
    "CONTEXT_AFTER",
    "CONTEXT_BEFORE",
    "PLUGIN_GROUP",
    "Detector",
    "Finding",
    "MatchBudget",
    "TooManyMatches",
    "builtin_detectors",
    "load_plugin_detectors",
]

CONTEXT_BEFORE = 60
CONTEXT_AFTER = 30
PLUGIN_GROUP = "caviard.detectors"

# Up to two separators inside a number: spaces, no-break spaces, dots or hyphens.
_OPT_SEP = "[ \u00a0\u202f.\\-]{0,2}"
_OPT_SPACE = "[ \u00a0\u202f\\-]?"


@dataclass(frozen=True, slots=True)
class Finding:
    """An entity found in a text: type, span and score, never the value."""

    entity: str
    start: int
    end: int
    score: float
    detector: str


class TooManyMatches(Exception):
    """One text produced more regular expression matches than its budget allows."""


@dataclass
class MatchBudget:
    """Matches one text may still produce: past it, the text is replaced whole.

    Validating a match costs a checksum or an address parse, and each finding a
    pseudonym: an input dense with candidates would otherwise take seconds.
    """

    remaining: int

    def spend(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise TooManyMatches


@dataclass(frozen=True)
class Detector:
    """A bounded regular expression plus validation and context rules.

    ``triggers`` are lowercase substrings: when given, the pattern only runs if
    one of them occurs, which keeps unrelated texts cheap; ``requires`` lists
    substrings that must all occur, and ``min_digits`` how many ASCII digits the
    text must hold. ``group`` selects the part of the match to redact, for example
    the token after ``Bearer``.
    """

    name: str
    entity: str
    pattern: re.Pattern[str]
    validate: Callable[[str], bool] | None = None
    score: float = 0.9
    context: tuple[str, ...] = ()
    context_required: bool = False
    context_boost: float = 0.1
    triggers: tuple[str, ...] = ()
    group: int = 0
    requires: tuple[str, ...] = ()
    min_digits: int = 0

    def find(
        self, text: str, lowered: str, hint: str = "", budget: MatchBudget | None = None
    ) -> Iterator[Finding]:
        """Yield validated findings; ``lowered`` must be ``text.lower()``.

        Every match spends one unit of ``budget``, which raises TooManyMatches once
        exhausted.
        """
        if self.triggers and not any(trigger in lowered for trigger in self.triggers):
            return
        if self.requires and not all(needed in lowered for needed in self.requires):
            return
        if self.min_digits and digit_count(lowered) < self.min_digits:
            return
        yield from self._matches(text, hint, budget)

    def _matches(self, text: str, hint: str, budget: MatchBudget | None) -> Iterator[Finding]:
        """The findings of the pattern, without the trigger checks of :meth:`find`."""
        for match in self.pattern.finditer(text):
            if budget is not None:
                budget.spend()
            start, end = match.span(self.group)
            if start >= end:
                continue
            if self.validate is not None and not self.validate(text[start:end]):
                continue
            in_context = bool(self.context) and _has_context(text, start, end, self.context, hint)
            if self.context_required and not in_context:
                continue
            score = min(1.0, self.score + (self.context_boost if in_context else 0.0))
            yield Finding(self.entity, start, end, score, self.name)


def digit_count(text: str) -> int:
    """How many ASCII digits ``text`` holds."""
    return sum(map(text.count, "0123456789"))


def _has_context(text: str, start: int, end: int, words: tuple[str, ...], hint: str) -> bool:
    # Lowered after slicing, so offsets stay valid whatever the Unicode content.
    before = text[max(0, start - CONTEXT_BEFORE) : start]
    after = text[end : end + CONTEXT_AFTER]
    window = f"{hint} {before} {after}".lower()
    return any(word in window for word in words)


def _numeric(pattern: str) -> re.Pattern[str]:
    """Compile a numeric pattern in which ``~`` marks one optional separator."""
    return re.compile(pattern.replace("~", _OPT_SEP))


def _routable_ip(raw: str) -> bool:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified)


def _routable_ipv6(raw: str) -> bool:
    # Hexadecimal words around "::" parse as addresses too (a::b, Bad::Cafe); the
    # addresses found in logs hold digits.
    if not any(char.isdigit() for char in raw):
        return False
    if sum(char in string.hexdigits for char in raw) < 4:
        return False
    return _routable_ip(raw)


def _iban_ok(raw: str) -> bool:
    # Lowercase text must start with a known IBAN country: the checksum alone accepts
    # one random string in 97.
    country = raw[:2]
    if not country.isupper() and country.upper() not in checksums.IBAN_LENGTHS:
        return False
    return checksums.iban_ok(raw)


# Secrets with a recognisable prefix: OpenAI, Anthropic and others (sk-), AWS, GitHub,
# Slack, Stripe, Google, Hugging Face, Groq, xAI, GitLab, PyPI, npm, Perplexity,
# LangSmith, Pinecone, Tavily and Replicate.
_API_KEY = re.compile(
    r"(?<![A-Za-z0-9_\-])(?:"
    r"sk-(?:proj-|svcacct-|admin-|ant-)?[A-Za-z0-9_\-]{20,400}"
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{36,255}"
    r"|github_pat_[A-Za-z0-9_]{22,255}"
    r"|xox[abprs]-[A-Za-z0-9\-]{10,255}"
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}"
    r"|AIza[0-9A-Za-z_\-]{35}"
    r"|hf_[A-Za-z0-9]{30,64}"
    r"|gsk_[A-Za-z0-9]{20,255}"
    r"|xai-[A-Za-z0-9]{20,255}"
    r"|glpat-[A-Za-z0-9_\-]{20,255}"
    r"|pypi-[A-Za-z0-9_\-]{50,400}"
    r"|npm_[A-Za-z0-9]{36,255}"
    r"|pplx-[A-Za-z0-9]{20,255}"
    r"|lsv2_(?:pt|sk)_[A-Za-z0-9_]{20,255}"
    r"|pcsk_[A-Za-z0-9_]{20,255}"
    r"|tvly-[A-Za-z0-9_\-]{20,255}"
    r"|r8_[A-Za-z0-9]{20,255}"
    r")(?![A-Za-z0-9_\-])"
)
# PEM and PGP private keys: the body stops at the next "-----", so an unterminated block
# is still covered and repeated headers stay linear.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN[A-Z ]{0,40} PRIVATE KEY(?: BLOCK)?-----"
    r"(?:(?!-----)[\s\S]){0,16384}"
    r"(?:-----END[A-Z ]{0,40} PRIVATE KEY(?: BLOCK)?-----)?"
)
# A placeholder glued to a token ("Bearer [SECRET]abc..."), matched with it so that it
# cannot shield the token.
_GLUED = r"(?:\[[A-Z][A-Z_]{1,31}(?::[a-z2-7]{6,32}|:\.\.\.[A-Za-z0-9]{1,8})?\])?"
_BEARER = re.compile(rf"(?i)(?<![a-z0-9])bearer[ \t]+({_GLUED}[A-Za-z0-9._~+/\-]{{16,4096}}=*)")
_BASIC = re.compile(
    rf"(?i)(?<![a-z0-9])basic[ \t]+({_GLUED}[A-Za-z0-9+/]{{12,1024}}={{0,2}})(?![A-Za-z0-9+/=])"
)
# "Authorization: Token ..." (Django REST framework and others).
_TOKEN_SCHEME = re.compile(
    rf"(?i)(?<![a-z0-9])token[ \t]+({_GLUED}[A-Za-z0-9._~+/\-]{{16,4096}}=*)"
)
# Values that are no secret: flags, nulls and type annotations ("password: str").
_NOT_A_VALUE = (
    "(?:true|false|null|none|undefined|str|int|bytes|string|any|object|optional"
    "|secretstr|secretbytes)"
)
# A character of a secret value. A closing bracket ends the value when what follows it
# cannot continue a value, as in "connect(password=...)"; the field-name rule of the
# redactor reads values the same way.
_VALUE_CHAR = r"""(?:[^\s"'&,;)\]}]|[)\]}](?![\s"'&,;)\]}.]|$))"""
# A secret written after its name, which may have prefixes and suffixes (DB_PASSWORD,
# AWS_SECRET_ACCESS_KEY, client-secret) or brackets, as in form bodies (user[password]).
_ASSIGNMENT = re.compile(
    r"(?i)(?:(?<=%5b)|(?<![a-z0-9_\-]))(?:[a-z0-9]{1,24}[_\-]){0,4}"
    r"(?:password|passwd|pwd|mdp|mot de passe|secret|api[_\-]?key|access[_\-]?token"
    r"|auth[_\-]?token|private[_\-]?key|access[_\-]?key)"
    r"(?:[_\-][a-z0-9]{1,24}){0,3}(?:\]|%5d)?"  # user[password]=, user%5Bpassword%5D=
    r"[\"']?[ \t]*[=:][ \t]*[\"']?"
    rf"(?!{_NOT_A_VALUE}(?:[\s\"'&,;)\]|=\[]|$))({_VALUE_CHAR}{{4,256}})"
)
# The password of a URL (the user name may be empty: redis://:password@host); it may
# hold "@", the last one before the host ends it.
_URL_CREDENTIALS = re.compile(r"(?<=://)[^/\s:@]{0,64}:([^/\s]{1,128})@")
_JWT = re.compile(
    r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{5,8000}\.eyJ[A-Za-z0-9_\-]{5,16000}"
    r"\.[A-Za-z0-9_\-]{0,8000}(?![A-Za-z0-9_\-])"
)
# Unicode letters are allowed (RFC 6531 addresses, IDN domains): an ASCII-only local
# part would leave "inè" of "inès.robert@exemple.fr" in clear. Escaped letters too, as
# JSON (fran\u00e7ois) or Python bytes (fran\xc3\xa7ois) print them: a second, slower
# pattern, only run on texts that hold such escapes.
_ESCAPED = r"\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}"
_EMAIL = re.compile(
    r"(?<![\w.%+\-])[\w.%+\-]{1,64}@"
    r"(?:[^\W_](?:[\w\-]{0,61}[^\W_])?\.){1,8}"
    r"[^\W\d_]{2,24}(?![\w\-])"
)
# Never starting right after a backslash: inside a run of escapes, every position would
# start a scan of the next 64 units (a 1 MB run of escapes took seconds).
_EMAIL_ESCAPED = re.compile(
    rf"(?<![\w.%+\-\\])(?:[\w.%+\-]|{_ESCAPED}){{1,64}}@"
    rf"(?:(?:[^\W_]|{_ESCAPED})(?:(?:[\w\-]|{_ESCAPED}){{0,61}}(?:[^\W_]|{_ESCAPED}))?\.){{1,8}}"
    r"[^\W\d_]{2,24}(?![\w\-])"
)
# Numbers: the first character comes before the lookbehind, which checks the one
# before it; the engine can then skip the positions that cannot start a match.
_NIR = _numeric(
    r"[1-478](?<![0-9A-Za-z][1-478])~[0-9]{2}~[0-9]{2}~(?:[0-9]{2}|2[ABab])~[0-9]{3}~[0-9]{3}"
    r"~[0-9]{2}(?![0-9])"
)
_IBAN = re.compile(
    rf"(?<![A-Za-z0-9])[A-Za-z]{{2}}[0-9]{{2}}(?:{_OPT_SPACE}[A-Za-z0-9]{{4}}){{2,7}}"
    rf"(?:{_OPT_SPACE}[A-Za-z0-9]{{1,4}})?(?![A-Za-z0-9])"
)
# Numbers glued to letters (hexadecimal identifiers, tokens) are not identifiers.
_CARD = re.compile(r"[0-9](?<![0-9A-Za-z][0-9])(?:[ \u00a0\-]?[0-9]){11,18}(?![0-9A-Za-z])")
_SIRET = _numeric(r"[0-9](?<![0-9A-Za-z][0-9])[0-9]{2}~[0-9]{3}~[0-9]{3}~[0-9]{5}(?![0-9A-Za-z])")
_SIREN = _numeric(r"[0-9](?<![0-9A-Za-z][0-9])[0-9]{2}~[0-9]{3}~[0-9]{3}(?![0-9A-Za-z])")
_RPPS = re.compile(r"[0-9](?<![0-9A-Za-z][0-9])[0-9]{10}(?![0-9A-Za-z])")
# +33, (+33), 0033 or 0, then nine digits.
_PHONE = _numeric(
    r"[+0(](?<![0-9A-Za-z+][+0(])"
    r"(?:(?<=\()\+33\)~(?:\(0\)~)?|(?<=\+)33~(?:\(0\)~)?|(?<=0)(?:033~(?:\(0\)~)?)?)"
    r"[1-9](?:~[0-9]{2}){4}(?![0-9A-Za-z])"
)
_IPV4 = re.compile(
    r"(?<![0-9A-Za-z.])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9A-Za-z]|\.[0-9])"
)
_IPV6 = re.compile(r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:.])")

_NIR_CONTEXT = ("sécu", "secu", "nir", "sécurité sociale", "securite sociale", "insee", "assuré")
_IBAN_CONTEXT = ("iban", "rib", "virement", "bancaire", "compte")
_CARD_CONTEXT = (
    "carte",
    "card",
    "visa",
    "mastercard",
    "amex",
    "american express",
    "paiement",
    "payment",
    "cb ",
    "cvv",
    "cvc",
    "expir",
)
_SIRET_CONTEXT = (
    "siret",
    "siren",
    "établissement",
    "etablissement",
    "entreprise",
    "société",
    "societe",
    "kbis",
    "fournisseur",
)
_SIREN_CONTEXT = ("siren", "sirene", "rcs", "société", "societe", "entreprise", "kbis", "tva")
_RPPS_CONTEXT = (
    "rpps",
    "médecin",
    "medecin",
    "praticien",
    "docteur",
    "dr ",
    "dr.",
    "pharmacien",
    "infirmi",
    "sage-femme",
    "kiné",
    "kine",
    "chirurgien",
    "ordonnance",
    "prescri",
)
_PHONE_CONTEXT = (
    "tél",
    "tel",
    "téléphone",
    "telephone",
    "portable",
    "mobile",
    "joindre",
    "appeler",
    "phone",
)
_API_KEY_TRIGGERS = (
    "sk-",
    "akia",
    "asia",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xox",
    "_live_",
    "_test_",
    "aiza",
    "hf_",
    "gsk_",
    "xai-",
    "glpat-",
    "pypi-",
    "npm_",
    "pplx-",
    "lsv2_",
    "pcsk_",
    "tvly-",
    "r8_",
)
_ASSIGNMENT_TRIGGERS = (
    "password",
    "passwd",
    "pwd",
    "mdp",
    "mot de passe",
    "secret",
    "key",
    "token",
)

_BUILTIN: tuple[Detector, ...] = (
    Detector("api-key", E.SECRET, _API_KEY, score=0.99, triggers=_API_KEY_TRIGGERS),
    Detector("private-key", E.SECRET, _PRIVATE_KEY, score=0.99, triggers=("private key",)),
    Detector("bearer-token", E.SECRET, _BEARER, score=0.97, triggers=("bearer",), group=1),
    Detector(
        "basic-auth",
        E.SECRET,
        _BASIC,
        score=0.9,
        context=("authorization",),
        context_required=True,
        context_boost=0.07,
        triggers=("basic",),
        group=1,
    ),
    Detector(
        "token-auth",
        E.SECRET,
        _TOKEN_SCHEME,
        score=0.9,
        context=("authorization",),
        context_required=True,
        context_boost=0.07,
        triggers=("token",),
        group=1,
    ),
    Detector(
        "credential", E.SECRET, _ASSIGNMENT, score=0.95, triggers=_ASSIGNMENT_TRIGGERS, group=1
    ),
    Detector("url-credentials", E.SECRET, _URL_CREDENTIALS, score=0.97, triggers=("://",), group=1),
    Detector("jwt", E.JWT, _JWT, score=0.98, triggers=("eyj",)),
    Detector("email", E.EMAIL, _EMAIL, score=0.92, triggers=("@",)),
    Detector(
        "email-escaped",
        E.EMAIL,
        _EMAIL_ESCAPED,
        score=0.92,
        triggers=("\\u", "\\x"),
        requires=("@",),
    ),
    Detector(
        "fr-nir",
        E.FR_NIR,
        _NIR,
        checksums.nir_ok,
        score=0.95,
        context=_NIR_CONTEXT,
        context_boost=0.04,
        min_digits=13,
    ),
    Detector(
        "iban",
        E.IBAN,
        _IBAN,
        _iban_ok,
        score=0.95,
        context=_IBAN_CONTEXT,
        context_boost=0.04,
        min_digits=2,
    ),
    Detector(
        "fr-siret",
        E.FR_SIRET,
        _SIRET,
        checksums.siret_ok,
        score=0.6,
        context=_SIRET_CONTEXT,
        context_required=True,
        context_boost=0.3,
        min_digits=14,
    ),
    Detector(
        "card",
        E.CARD,
        _CARD,
        checksums.card_ok,
        score=0.6,
        context=_CARD_CONTEXT,
        context_required=True,
        context_boost=0.3,
        min_digits=12,
    ),
    Detector(
        "fr-siren",
        E.FR_SIREN,
        _SIREN,
        checksums.siren_ok,
        score=0.6,
        context=_SIREN_CONTEXT,
        context_required=True,
        context_boost=0.3,
        min_digits=9,
    ),
    Detector(
        "fr-rpps",
        E.FR_RPPS,
        _RPPS,
        checksums.rpps_ok,
        score=0.6,
        context=_RPPS_CONTEXT,
        context_required=True,
        context_boost=0.3,
        min_digits=11,
    ),
    Detector(
        "fr-phone",
        E.FR_PHONE,
        _PHONE,
        score=0.85,
        context=_PHONE_CONTEXT,
        context_boost=0.05,
        min_digits=10,
    ),
    Detector("ipv4", E.IP_ADDRESS, _IPV4, _routable_ip, score=0.8, triggers=(".",)),
    Detector("ipv6", E.IP_ADDRESS, _IPV6, _routable_ipv6, score=0.8, triggers=(":",)),
)


def builtin_detectors() -> tuple[Detector, ...]:
    """The detectors shipped with caviard, in priority order for score ties."""
    return _BUILTIN


def load_plugin_detectors() -> list[Detector]:
    """Load detectors registered under the ``caviard.detectors`` entry point group.

    An entry point may reference a Detector, an iterable of detectors, or a
    callable returning either.
    """
    loaded: list[Detector] = []
    for entry_point in metadata.entry_points(group=PLUGIN_GROUP):
        obj = entry_point.load()
        if callable(obj) and not isinstance(obj, Detector):
            obj = obj()
        items = [obj] if isinstance(obj, Detector) else list(obj)
        for item in items:
            if not isinstance(item, Detector):
                raise CaviardError(
                    f"detector plugin {entry_point.name!r} returned a non-Detector object"
                )
            loaded.append(item)
    return loaded
