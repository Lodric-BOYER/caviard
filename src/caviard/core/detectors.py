"""Built-in detectors.

A detector combines a bounded regular expression, an optional validation
function (checksum, address parser) and optional context words. Detectors
whose validation is weak (Luhn alone accepts one random number in ten)
require a context word near the match.
"""

from __future__ import annotations

import ipaddress
import re
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
    "builtin_detectors",
    "load_plugin_detectors",
]

CONTEXT_BEFORE = 60
CONTEXT_AFTER = 30
PLUGIN_GROUP = "caviard.detectors"

# One optional separator inside a number: space, no-break spaces, dot or hyphen.
_OPT_SEP = "[ \u00a0\u202f.\\-]?"
_OPT_SPACE = "[ \u00a0\u202f]?"


@dataclass(frozen=True, slots=True)
class Finding:
    """An entity found in a text: type, span and score, never the value."""

    entity: str
    start: int
    end: int
    score: float
    detector: str


@dataclass(frozen=True)
class Detector:
    """A bounded regular expression plus validation and context rules.

    ``triggers`` are lowercase substrings: when given, the pattern only runs if
    one of them occurs, which keeps unrelated texts cheap. ``group`` selects
    the part of the match to redact, for example the token after ``Bearer``.
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

    def find(self, text: str, lowered: str, hint: str = "") -> Iterator[Finding]:
        """Yield validated findings; ``lowered`` must be ``text.lower()``."""
        if self.triggers and not any(trigger in lowered for trigger in self.triggers):
            return
        for match in self.pattern.finditer(text):
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


# Secrets with a recognisable prefix.
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
    r")(?![A-Za-z0-9_\-])"
)
# PEM private key: the body stops at the next "-----", so an unterminated block
# is still covered and repeated headers stay linear.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN[A-Z ]{0,40} PRIVATE KEY-----"
    r"(?:(?!-----)[\s\S]){0,16384}"
    r"(?:-----END[A-Z ]{0,40} PRIVATE KEY-----)?"
)
_BEARER = re.compile(r"(?<![A-Za-z0-9])[Bb]earer[ \t]+([A-Za-z0-9._~+/\-]{16,4096}=*)")
_BASIC = re.compile(
    r"(?<![A-Za-z0-9])[Bb]asic[ \t]+([A-Za-z0-9+/]{12,1024}={0,2})(?![A-Za-z0-9+/=])"
)
_ASSIGNMENT = re.compile(
    r"(?i)(?<![a-z0-9_])"
    r"(?:password|passwd|pwd|mdp|mot de passe|secret|api[_\-]?key|access[_\-]?token"
    r"|auth[_\-]?token|client[_\-]?secret)"
    r"[\"']?[ \t]*[=:][ \t]*[\"']?([^\s\"'&,;]{4,256})"
)
_URL_CREDENTIALS = re.compile(r"(?<=://)[^/\s:@]{1,64}:([^/\s@]{1,128})@")
_JWT = re.compile(
    r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{5,8000}\.eyJ[A-Za-z0-9_\-]{5,16000}"
    r"\.[A-Za-z0-9_\-]{0,8000}(?![A-Za-z0-9_\-])"
)
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24}(?![A-Za-z0-9\-])"
)
_NIR = _numeric(
    r"(?<![0-9A-Za-z])[1-478]~[0-9]{2}~[0-9]{2}~(?:[0-9]{2}|2[ABab])~[0-9]{3}~[0-9]{3}~[0-9]{2}"
    r"(?![0-9])"
)
_IBAN = re.compile(
    rf"(?<![A-Za-z0-9])[A-Z]{{2}}[0-9]{{2}}(?:{_OPT_SPACE}[A-Z0-9]{{4}}){{2,7}}"
    rf"(?:{_OPT_SPACE}[A-Z0-9]{{1,4}})?(?![A-Za-z0-9])"
)
# Numbers glued to letters (hexadecimal identifiers, tokens) are not identifiers.
_CARD = re.compile(r"(?<![0-9A-Za-z])(?:[0-9][ \u00a0\-]?){11,18}[0-9](?![0-9A-Za-z])")
_SIRET = _numeric(r"(?<![0-9A-Za-z])[0-9]{3}~[0-9]{3}~[0-9]{3}~[0-9]{5}(?![0-9A-Za-z])")
_SIREN = _numeric(r"(?<![0-9A-Za-z])[0-9]{3}~[0-9]{3}~[0-9]{3}(?![0-9A-Za-z])")
_RPPS = re.compile(r"(?<![0-9A-Za-z])[0-9]{11}(?![0-9A-Za-z])")
_PHONE = _numeric(
    r"(?<![0-9A-Za-z+])(?:(?:\+|00)33~(?:\(0\)~)?|0)[1-9](?:~[0-9]{2}){4}(?![0-9A-Za-z])"
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
        "credential", E.SECRET, _ASSIGNMENT, score=0.95, triggers=_ASSIGNMENT_TRIGGERS, group=1
    ),
    Detector("url-credentials", E.SECRET, _URL_CREDENTIALS, score=0.97, triggers=("://",), group=1),
    Detector("jwt", E.JWT, _JWT, score=0.98, triggers=("eyj",)),
    Detector("email", E.EMAIL, _EMAIL, score=0.92, triggers=("@",)),
    Detector(
        "fr-nir",
        E.FR_NIR,
        _NIR,
        checksums.nir_ok,
        score=0.95,
        context=_NIR_CONTEXT,
        context_boost=0.04,
    ),
    Detector(
        "iban",
        E.IBAN,
        _IBAN,
        checksums.iban_ok,
        score=0.95,
        context=_IBAN_CONTEXT,
        context_boost=0.04,
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
    ),
    Detector(
        "fr-phone", E.FR_PHONE, _PHONE, score=0.85, context=_PHONE_CONTEXT, context_boost=0.05
    ),
    Detector("ipv4", E.IP_ADDRESS, _IPV4, _routable_ip, score=0.8, triggers=(".",)),
    Detector("ipv6", E.IP_ADDRESS, _IPV6, _routable_ip, score=0.8, triggers=(":",)),
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
