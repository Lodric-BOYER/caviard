"""Exceptions and warnings. Messages never contain analysed values."""

from __future__ import annotations

__all__ = ["CaviardError", "CaviardWarning", "PolicyError", "RedactionError"]


class CaviardError(Exception):
    """Base class for caviard errors."""


class PolicyError(CaviardError, ValueError):
    """The redaction policy is invalid."""


class RedactionError(CaviardError):
    """Redaction could not be completed; callers must fail closed."""


class CaviardWarning(UserWarning):
    """Non-fatal configuration issue, such as a missing pseudonym key."""
