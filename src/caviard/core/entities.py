"""Entity type names used in placeholders and statistics."""

from __future__ import annotations

from typing import Final

SECRET: Final = "SECRET"  # noqa: S105 (entity name, not a password)
JWT: Final = "JWT"
EMAIL: Final = "EMAIL"
FR_NIR: Final = "FR_NIR"
IBAN: Final = "IBAN"
CARD: Final = "CARD"
FR_SIRET: Final = "FR_SIRET"
FR_SIREN: Final = "FR_SIREN"
FR_RPPS: Final = "FR_RPPS"
FR_PHONE: Final = "FR_PHONE"
IP_ADDRESS: Final = "IP_ADDRESS"

# Pseudo-entities produced by key, field and size rules rather than detectors.
REDACTED: Final = "REDACTED"
TOO_LARGE: Final = "TOO_LARGE"
QUARANTINED: Final = "QUARANTINED"
DROPPED: Final = "DROPPED"

BUILTIN: Final[tuple[str, ...]] = (
    SECRET,
    JWT,
    EMAIL,
    FR_NIR,
    IBAN,
    CARD,
    FR_SIRET,
    FR_SIREN,
    FR_RPPS,
    FR_PHONE,
    IP_ADDRESS,
)
SPECIAL: Final[tuple[str, ...]] = (REDACTED, TOO_LARGE, QUARANTINED, DROPPED)
