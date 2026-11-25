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
_MAX_NESTING = 64  # deeper containers are printed, then redacted as text
_MAX_ITEMS = 10_000  # larger arguments are merged first, then redacted as text
_STANDARD_ATTRIBUTES = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message",
    "asctime",
    "taskName",
}

Processor = Callable[[Any, str, MutableMapping[str, Any]], MutableMapping[str, Any]]


class RedactingFilter(logging.Filter):
    """Redact the message, exception text, stack and extra fields of each record.

    The record is modified in place, so the handlers that run after this one
    see the redacted version too. Each argument is redacted on its own, then
    merged into the message (``record.args`` is cleared), and the exception is
    rendered as redacted text (``record.exc_info`` is cleared). Redaction is
    idempotent: a record that goes through several filters is not changed again.
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
            record.msg = redactor.redact_value(self._message(record))
            record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        record.exc_info = None  # formatters fall back to the redacted exc_text
        if record.exc_text:
            record.exc_text = redactor.redact_value(record.exc_text)
        if record.stack_info:
            record.stack_info = redactor.redact_value(record.stack_info)
        extras = {key: _extra(getattr(record, key)) for key in _extra_keys(record)}
        if extras:
            redacted = redactor.redact_attributes(extras)
            for key in extras:
                if key in redacted:
                    setattr(record, key, redacted[key])
                else:
                    delattr(record, key)

    def _message(self, record: logging.LogRecord) -> str:
        """The message, each argument redacted on its own before they are merged.

        Dictionaries and lists keep their structure this way, so the field-name
        rules apply to them, and a precision such as ``%.4s`` cuts a placeholder
        rather than a value. The caller redacts the merged text again, which covers
        a value split across several arguments.
        """
        args = record.args
        if not args:
            return record.getMessage()
        redactor = self.redactor
        values: object
        try:
            items = _Items(_MAX_ITEMS)
            if isinstance(args, tuple):
                values = tuple(_argument(arg, redactor, items) for arg in args)
            else:  # a mapping, for "%(name)s" formats
                values = _argument(args, redactor, items)
            return str(record.msg) % values
        except Exception:
            # "%d" given a placeholder, or arguments too large to walk: the merged
            # text is redacted instead.
            return record.getMessage()


class _Items:
    """How many more container items the arguments of one message may hold."""

    __slots__ = ("remaining",)

    def __init__(self, remaining: int) -> None:
        self.remaining = remaining

    def spend(self) -> None:
        self.remaining -= 1
        if self.remaining < 0:
            raise _TooManyItems


class _TooManyItems(Exception):
    """The arguments of one message hold too many items to be redacted one by one."""


class _Rendered:
    """An argument that is not plain data, printed redacted with ``%s``, ``%r`` or ``%a``."""

    __slots__ = ("_redactor", "_value")

    def __init__(self, value: object, redactor: Redactor) -> None:
        self._value = value
        self._redactor = redactor

    def __str__(self) -> str:
        return str(self._redactor.redact_value(str(self._value)))

    def __repr__(self) -> str:
        return str(self._redactor.redact_value(repr(self._value)))


def _argument(value: object, redactor: Redactor, items: _Items) -> object:
    """One argument of a message, redacted on its own."""
    if value is None or isinstance(value, str | int | float):
        return redactor.redact_value(value)
    if isinstance(value, Mapping | list | tuple | set | frozenset):
        return redactor.redact_value(_plain(value, items, 0))
    return _Rendered(value, redactor)


def _plain(value: object, items: _Items, depth: int) -> object:
    """Containers rebuilt with plain data; other objects become their ``repr``, as printed."""
    if value is None or isinstance(value, str | int | float):
        return value
    if depth < _MAX_NESTING:
        if isinstance(value, Mapping):
            result: dict[object, object] = {}
            for key, item in value.items():
                items.spend()
                result[_hashable(key)] = _plain(item, items, depth + 1)
            return result
        if isinstance(value, list | tuple):
            elements: list[object] = []
            for item in value:
                items.spend()
                elements.append(_plain(item, items, depth + 1))
            return tuple(elements) if isinstance(value, tuple) else elements
        if isinstance(value, set | frozenset):
            members: list[object] = []
            for item in value:
                items.spend()
                members.append(_hashable(item))
            return frozenset(members) if isinstance(value, frozenset) else set(members)
    return repr(value)


def _extra(value: object) -> object:
    """An extra field as plain data; other objects become their text, as ``%(name)s`` prints."""
    if value is None or isinstance(value, str | int | float):
        return value
    if isinstance(value, Mapping | list | tuple | set | frozenset):
        try:
            return _plain(value, _Items(_MAX_ITEMS), 0)
        except _TooManyItems:
            return repr(value)  # redacted as text
    return str(value)


def _hashable(value: object) -> object:
    """A mapping key or set member as plain data that stays hashable."""
    if value is None or isinstance(value, str | int | float):
        return value
    if isinstance(value, tuple):
        return tuple(_hashable(item) for item in value)
    return repr(value)


def _extra_keys(record: logging.LogRecord) -> list[str]:
    """Attributes added with ``extra=``, which handlers and formatters may export.

    Private ones (leading underscore) are included when they hold plain data:
    OpenTelemetry's LoggingHandler and JSON formatters export them too. Private
    objects are left alone, as libraries keep their own state there.
    """
    return [
        key
        for key, value in vars(record).items()
        if key not in _STANDARD_ATTRIBUTES and (key[:1] != "_" or _private_data(value))
    ]


def _private_data(value: object) -> bool:
    """Whether a private attribute holds plain data; never raises. Too large to tell is
    taken as data, which is redacted rather than left in clear."""
    try:
        return _is_plain(value, _Items(_MAX_ITEMS), 0)
    except _TooManyItems:
        return True
    except Exception:
        return False


def _is_plain(value: object, items: _Items, depth: int) -> bool:
    """True for texts, numbers, None and containers of them."""
    if value is None or isinstance(value, str | int | float):
        return True
    if depth >= _MAX_NESTING:
        return False
    if isinstance(value, Mapping):
        for key, item in value.items():
            items.spend()
            if not (_is_plain(key, items, depth + 1) and _is_plain(item, items, depth + 1)):
                return False
        return True
    if isinstance(value, list | tuple | set | frozenset):
        for item in value:
            items.spend()
            if not _is_plain(item, items, depth + 1):
                return False
        return True
    return False


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
