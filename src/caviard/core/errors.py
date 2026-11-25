"""Exceptions and warnings. Messages never contain analysed values."""

from __future__ import annotations

import os
import sys
import warnings

__all__ = ["CaviardError", "CaviardWarning", "PolicyError", "RedactionError", "warn"]

_PACKAGE = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.sep


class CaviardError(Exception):
    """Base class for caviard errors."""


class PolicyError(CaviardError, ValueError):
    """The redaction policy is invalid."""


class RedactionError(CaviardError):
    """Redaction could not be completed; callers must fail closed."""


class CaviardWarning(UserWarning):
    """Non-fatal configuration issue, such as a missing pseudonym key."""


def warn(message: str) -> None:
    """Emit a CaviardWarning attributed to the first caller outside caviard.

    The warning then points at the line that built the redactor, exporter or
    callback, whatever the integration in between.
    """
    level = 2
    frame = sys._getframe(1)
    while frame is not None and os.path.abspath(frame.f_code.co_filename).startswith(_PACKAGE):
        frame = frame.f_back  # type: ignore[assignment]
        level += 1
    warnings.warn(message, CaviardWarning, stacklevel=level)
