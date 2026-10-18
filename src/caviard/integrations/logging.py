"""Standard ``logging`` integration and a structlog processor.

Attach the filter to handlers, so that records propagated from child loggers
are covered too::

    import logging
    from caviard.integrations.logging import RedactingFilter

    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter.from_policy("caviard.toml"))
    logging.getLogger().addHandler(handler)

or call ``install()`` once logging is configured, to add one filter to every
handler of a logger (the root logger by default).

With structlog, add ``structlog_processor()`` to the processor chain instead,
after ``format_exc_info`` and before the renderer.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, MutableMapping
from pathlib import Path
from typing import Any

from caviard.core import entities as E
from caviard.core.errors import CaviardError
from caviard.core.policy import Policy
from caviard.core.pseudonym import SecretKey
from caviard.core.redactor import Redactor

__all__ = ["QUARANTINED", "RedactingFilter", "install", "structlog_processor"]

QUARANTINED = "[QUARANTINED]"
_STANDARD_ATTRIBUTES = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message",
    "asctime",
    "taskName",
}

Processor = Callable[[Any, str, MutableMapping[str, Any]], MutableMapping[str, Any]]


class RedactingFilter(logging.Filter):
    """Redact the message, exception text, stack and extra fields of each record.

    The record is modified in place, so the handlers that run after this one
    see the redacted version too. Arguments are merged into the message first
    (``record.args`` is cleared) and the exception is rendered as redacted text
    (``record.exc_info`` is cleared). Redaction is idempotent: a record that
    goes through several filters is not changed again.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        redactor: Redactor | None = None,
        pseudonym_key: bytes | str | SecretKey | None = None,
        name: str = "",
    ) -> None:
        super().__init__(name)
        self.redactor = (
            redactor if redactor is not None else Redactor(policy, pseudonym_key=pseudonym_key)
        )

    @classmethod
    def from_policy(cls, path: str | Path, **kwargs: Any) -> RedactingFilter:
        """Build the filter from a policy file."""
        return cls(Policy.load(path), **kwargs)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            self._redact(record)
        except Exception:
            self.redactor.stats.add(E.QUARANTINED)
            record.msg = QUARANTINED
            record.args = None
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
            for key in _extra_keys(record):
                setattr(record, key, QUARANTINED)
        return True

    def _redact(self, record: logging.LogRecord) -> None:
        redactor = self.redactor
        if isinstance(record.msg, Mapping) and not record.args:
            record.msg = redactor.redact_attributes(record.msg)  # structlog event dicts
        else:
            record.msg = redactor.redact_value(record.getMessage())
            record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        record.exc_info = None  # formatters fall back to the redacted exc_text
        if record.exc_text:
            record.exc_text = redactor.redact_text(record.exc_text)
        if record.stack_info:
            record.stack_info = redactor.redact_text(record.stack_info)
        extras = {key: getattr(record, key) for key in _extra_keys(record)}
        if extras:
            redacted = redactor.redact_attributes(extras)
            for key in extras:
                if key in redacted:
                    setattr(record, key, redacted[key])
                else:
                    delattr(record, key)


def _extra_keys(record: logging.LogRecord) -> list[str]:
    """Attributes added with ``extra=``; private ones (leading underscore) are skipped."""
    return [key for key in vars(record) if key not in _STANDARD_ATTRIBUTES and key[:1] != "_"]


def install(
    policy: Policy | None = None,
    *,
    logger: logging.Logger | None = None,
    redactor: Redactor | None = None,
    pseudonym_key: bytes | str | SecretKey | None = None,
) -> RedactingFilter:
    """Add one RedactingFilter to every handler of ``logger`` (root by default)."""
    target = logger if logger is not None else logging.getLogger()
    if not target.handlers:
        raise CaviardError("the logger has no handler: configure logging first")
    redacting = RedactingFilter(policy, redactor=redactor, pseudonym_key=pseudonym_key)
    for handler in target.handlers:
        handler.addFilter(redacting)
    return redacting


def structlog_processor(
    policy: Policy | None = None,
    *,
    redactor: Redactor | None = None,
    pseudonym_key: bytes | str | SecretKey | None = None,
) -> Processor:
    """A structlog processor; place it after ``format_exc_info`` and before the renderer."""
    engine = redactor if redactor is not None else Redactor(policy, pseudonym_key=pseudonym_key)

    def processor(
        logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        try:
            return engine.redact_attributes(event_dict)
        except Exception:
            engine.stats.add(E.QUARANTINED)
            return {"event": QUARANTINED}

    return processor
