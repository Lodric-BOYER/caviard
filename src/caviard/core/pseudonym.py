"""Keyed pseudonyms: the same value always maps to the same short token.

A token is HMAC-SHA256(key, entity + value), encoded in lowercase base32 and
truncated. Without the key a token cannot be linked back to its value, even
by brute force over small spaces such as phone numbers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
from pathlib import Path

from caviard.core import entities as E
from caviard.core.errors import PolicyError

__all__ = [
    "MIN_KEY_BYTES",
    "Pseudonymizer",
    "SecretKey",
    "decode_key",
    "generate_key",
    "normalize",
    "resolve_key",
]

MIN_KEY_BYTES = 32
_HEX_KEY = re.compile(r"[0-9a-fA-F]{64,}")
_B64_KEY = re.compile(r"[A-Za-z0-9_\-]{43,}={0,2}")
_NON_DIGIT = re.compile(r"[^0-9]")
_SEPARATORS = re.compile(r"[\s.\-]")
_DIGIT_ENTITIES = frozenset({E.CARD, E.FR_SIREN, E.FR_SIRET, E.FR_RPPS})


class SecretKey:
    """A pseudonym key. Its value never appears in repr() or str()."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes) -> None:
        if len(value) < MIN_KEY_BYTES:
            raise PolicyError(
                f"pseudonym key is too short: at least {MIN_KEY_BYTES} bytes are required "
                "(create one with `caviard keygen`)"
            )
        self._value = bytes(value)

    @classmethod
    def generate(cls) -> SecretKey:
        """A random key, for example for a single process."""
        return cls(secrets.token_bytes(MIN_KEY_BYTES))

    def __repr__(self) -> str:
        return "SecretKey(<hidden>)"

    __str__ = __repr__


def generate_key() -> str:
    """Return a new random key (32 bytes) encoded as unpadded base64url."""
    return base64.urlsafe_b64encode(secrets.token_bytes(MIN_KEY_BYTES)).decode().rstrip("=")


def decode_key(text: str) -> bytes:
    """Decode a key given as hex, base64url or, as a last resort, raw text."""
    candidate = text.strip()
    if _HEX_KEY.fullmatch(candidate) and len(candidate) % 2 == 0:
        return bytes.fromhex(candidate)
    if _B64_KEY.fullmatch(candidate):
        try:
            return base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4))
        except (binascii.Error, ValueError):
            pass
    return candidate.encode("utf-8")


def resolve_key(env_name: str | None, key_file: str | None) -> SecretKey | None:
    """Load the key from a file (preferred) or from an environment variable."""
    if key_file:
        try:
            text = Path(key_file).read_text(encoding="utf-8")
        except OSError:
            raise PolicyError("cannot read the pseudonym key file") from None
        return SecretKey(decode_key(text))
    if env_name:
        text = os.environ.get(env_name, "")
        if text.strip():
            return SecretKey(decode_key(text))
    return None


def normalize(entity: str, value: str) -> str:
    """Canonical form, so that formatting variants share one pseudonym."""
    if entity == E.EMAIL:
        return value.strip().lower()
    if entity == E.FR_PHONE:
        digits = _NON_DIGIT.sub("", value)
        if digits.startswith("0033"):
            digits = digits[4:]
        elif digits.startswith("33") and len(digits) > 10:
            digits = digits[2:]
        return digits if digits.startswith("0") else "0" + digits
    if entity in _DIGIT_ENTITIES:
        return _NON_DIGIT.sub("", value)
    if entity in (E.IBAN, E.FR_NIR):
        return _SEPARATORS.sub("", value).upper()
    if entity == E.IP_ADDRESS:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            return value.strip()
    return value.strip()


class Pseudonymizer:
    """Computes tokens with a secret key. Stateless, hence thread-safe."""

    __slots__ = ("_key", "_length")

    def __init__(self, key: SecretKey, length: int = 12) -> None:
        if not 8 <= length <= 32:
            raise PolicyError("pseudonym length must be between 8 and 32")
        self._key = key._value
        self._length = length

    def token(self, entity: str, value: str) -> str:
        message = f"{entity}\x00{normalize(entity, value)}".encode()
        digest = hmac.new(self._key, message, hashlib.sha256).digest()
        return base64.b32encode(digest).decode("ascii").lower()[: self._length]
