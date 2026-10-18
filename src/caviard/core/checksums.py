"""Checksum validators for French and European identifiers.

Every validator takes the raw matched text (separators allowed) and returns
True only when the structure and the check digits are valid. Only ASCII
digits are accepted.
"""

from __future__ import annotations

import re

__all__ = [
    "IBAN_LENGTHS",
    "card_ok",
    "iban_ok",
    "luhn_ok",
    "nir_ok",
    "rpps_ok",
    "siren_ok",
    "siret_ok",
]

_NON_DIGIT = re.compile(r"[^0-9]")
_NIR_SEPARATORS = re.compile(r"[ \u00a0\u202f.\-]")
_IBAN_SEPARATORS = re.compile(r"[ \u00a0\u202f]")

# Registered IBAN lengths (ISO 13616) for European countries. Countries absent
# from the table only need a length between 15 and 34 characters.
# fmt: off
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AT": 20, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24,
    "DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GI": 23, "GL": 18, "GR": 27, "HR": 21, "HU": 28, "IE": 22,
    "IS": 26, "IT": 27, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27,
    "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24, "SE": 24,
    "SI": 19, "SK": 24, "SM": 27, "VA": 22,
}
# fmt: on


def luhn_ok(digits: str) -> bool:
    """Luhn (mod 10) check of a string made only of ASCII digits."""
    if not digits or not digits.isascii() or not digits.isdigit():
        return False
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if position % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def nir_ok(raw: str) -> bool:
    """French social security number (NIR): 13 characters and a 2-digit key.

    key = 97 - (number mod 97). Corsican departments 2A and 2B count as 19 and
    18. The first digit is the sex code (1, 2) or a temporary code (3, 4, 7, 8).
    """
    value = _NIR_SEPARATORS.sub("", raw).upper()
    if len(value) != 15 or not value.isascii():
        return False
    body, key = value[:13], value[13:]
    department = body[5:7]
    if department in ("2A", "2B"):
        body = body[:5] + ("19" if department == "2A" else "18") + body[7:]
    if not body.isdigit() or not key.isdigit() or body[0] not in "123478":
        return False
    return 97 - int(body) % 97 == int(key)


def siren_ok(raw: str) -> bool:
    """French company identifier (SIREN): 9 digits, Luhn."""
    digits = _NON_DIGIT.sub("", raw)
    return len(digits) == 9 and luhn_ok(digits)


def siret_ok(raw: str) -> bool:
    """French establishment identifier (SIRET): 14 digits, Luhn.

    La Poste establishments (SIREN 356 000 000) follow another rule: the sum of
    the digits is a multiple of 5.
    """
    digits = _NON_DIGIT.sub("", raw)
    if len(digits) != 14:
        return False
    if digits.startswith("356000000"):
        return sum(ord(char) - 48 for char in digits) % 5 == 0
    return luhn_ok(digits)


def rpps_ok(raw: str) -> bool:
    """French health professional identifier (RPPS): 11 digits, Luhn."""
    digits = _NON_DIGIT.sub("", raw)
    return len(digits) == 11 and luhn_ok(digits)


def card_ok(raw: str) -> bool:
    """Payment card number: 12 to 19 digits (Maestro starts at 12), Luhn."""
    digits = _NON_DIGIT.sub("", raw)
    return 12 <= len(digits) <= 19 and luhn_ok(digits)


def iban_ok(raw: str) -> bool:
    """IBAN (ISO 13616): country code, check digits, mod 97 equal to 1."""
    value = _IBAN_SEPARATORS.sub("", raw).upper()
    if not 15 <= len(value) <= 34 or not value.isascii() or not value.isalnum():
        return False
    if not value[:2].isalpha() or not value[2:4].isdigit():
        return False
    expected = IBAN_LENGTHS.get(value[:2])
    if expected is not None and len(value) != expected:
        return False
    rearranged = value[4:] + value[:4]
    return int("".join(str(int(char, 36)) for char in rearranged)) % 97 == 1
