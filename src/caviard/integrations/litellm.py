"""LiteLLM integration: a callback that redacts what LiteLLM hands to its loggers::

    import litellm
    from caviard.integrations.litellm import CaviardLogger

    litellm.callbacks = [CaviardLogger.from_policy("caviard.toml"), *other_callbacks]

CaviardLogger redacts LiteLLM's logging state (the ``kwargs`` dictionary that
every callback receives): messages, user and metadata values, raw request and
response bodies and the standard logging payload are replaced by redacted
copies. Callbacks receive a redacted copy of the response. The objects held by
the application, such as its message list and the response, are never modified.

On success (sync, async and streaming calls), LiteLLM calls ``logging_hook``
before any logging callback, so all of them are covered. On failure, LiteLLM
does not call it: CaviardLogger redacts the state in its own failure callback,
which protects the callbacks that run after it, so keep it first in
``litellm.callbacks``. For async calls, LiteLLM runs the legacy failure
callbacks (names such as ``"langfuse"`` in ``litellm.failure_callback`` and plain
functions) before the async ones: they are not covered, register loggers as
``CustomLogger`` instances instead.

Left unchanged on purpose: the exception object (its text is redacted in the
traceback and the logging payload), Python objects other than plain data in
the parameters (clients, callables) and ``standard_callback_dynamic_params``,
which holds per-request logger credentials. Every later callback sees the
redacted values, LiteLLM's spend tracking included: an end-user id that is an
email address is recorded as a pseudonym.
"""

from __future__ import annotations

import copy
import datetime
import decimal
import enum
import inspect
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError as exc:  # pragma: no cover - depends on the environment
    raise ImportError("this integration needs LiteLLM: pip install 'caviard[litellm]'") from exc

from caviard.core import entities as E
from caviard.core.errors import RedactionError
from caviard.core.policy import Policy
from caviard.core.pseudonym import SecretKey
from caviard.core.redactor import Redactor

__all__ = ["QUARANTINED", "CaviardLogger"]

QUARANTINED = "[QUARANTINED]"
# Entries made of user content: converted to plain data, then redacted.
_CONTENT_KEYS = frozenset(
    {
        "messages",
        "input",
        "prompt",
        "original_response",
        "traceback_exception",
        "additional_args",
        "standard_logging_object",
    }
)
# Responses: redacted copies keep their classes.
_RESPONSE_KEYS = frozenset({"complete_streaming_response", "async_complete_streaming_response"})
# Per-request logger credentials, read by the loggers themselves.
_PASSTHROUGH_KEYS = frozenset({"standard_callback_dynamic_params"})
_MAX_NESTING = 64
_INT_LIMIT = 100_000_000  # smaller integers cannot hold an identifier
_ATOMIC = (
    datetime.date | datetime.time | datetime.timedelta | decimal.Decimal | uuid.UUID | enum.Enum
)


class CaviardLogger(CustomLogger):  # type: ignore[misc,unused-ignore]
    """LiteLLM callback that redacts requests, responses and logging payloads."""

    def __init__(
        self,
        policy: Policy | None = None,
        *,
        redactor: Redactor | None = None,
        pseudonym_key: bytes | str | SecretKey | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.redactor = (
            redactor if redactor is not None else Redactor(policy, pseudonym_key=pseudonym_key)
        )

    @classmethod
    def from_policy(cls, path: str | Path, **kwargs: Any) -> CaviardLogger:
        """Build the callback from a policy file."""
        return cls(Policy.load(path), **kwargs)

    # Success: LiteLLM passes what these hooks return to every logging callback.

    def logging_hook(
        self, kwargs: dict[str, Any], result: Any, call_type: str
    ) -> tuple[dict[str, Any], Any]:
        return self._redact_state(kwargs), self._response(result)

    async def async_logging_hook(
        self, kwargs: dict[str, Any], result: Any, call_type: str
    ) -> tuple[dict[str, Any], Any]:
        return self._redact_state(kwargs), self._response(result)

    # Failure: redact the shared state before the callbacks that follow.

    def log_failure_event(
        self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        self._redact_state(kwargs)

    async def async_log_failure_event(
        self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
    ) -> None:
        self._redact_state(kwargs)

    # Internals

    def _redact_state(self, kwargs: Any) -> Any:
        """Redact LiteLLM's logging dictionary in place (values are replaced, not changed).

        In place, because for async calls LiteLLM also runs its sync handler in a
        thread, which writes fresh payloads into the dictionary the async
        callbacks received; the next hook call redacts them again.
        """
        if not isinstance(kwargs, Mapping):
            return kwargs
        details = self._details(kwargs)
        if isinstance(kwargs, dict):
            kwargs.update(details)
            return kwargs
        return details

    def _details(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        """Redacted copy of LiteLLM's logging state; quarantined if redaction fails."""
        try:
            return self._redacted_details(kwargs)
        except Exception:
            self.redactor.stats.add(E.QUARANTINED)
            return _quarantined_details(kwargs)

    def _redacted_details(self, kwargs: Mapping[str, Any]) -> dict[str, Any]:
        others = {
            key: value
            for key, value in kwargs.items()
            if key not in _CONTENT_KEYS | _RESPONSE_KEYS | _PASSTHROUGH_KEYS
        }
        details = dict(kwargs)
        details.update(self._clean(others, "", 0, objects=False))
        for key in _CONTENT_KEYS & details.keys():
            value = details[key]
            if value is not None and not _is_lazy(value):
                details[key] = self._plain(value, key)
        for key in _RESPONSE_KEYS & details.keys():
            details[key] = self._response(details[key])
        return details

    def _response(self, result: Any) -> Any:
        """Redacted copy of a response; quarantined if redaction fails."""
        try:
            if result is None or isinstance(result, str | int | float | Mapping | list | tuple):
                return self._plain(result, "response")
            if _is_lazy(result):
                return QUARANTINED  # a stream: its content is logged once assembled
            if type(result).__name__ == "EmbeddingResponse":
                return result  # vectors only; the input is redacted with the request
            return self._clean(copy.deepcopy(result), "response", 0, objects=True)
        except Exception:
            self.redactor.stats.add(E.QUARANTINED)
            return QUARANTINED

    def _plain(self, value: Any, hint: str) -> Any:
        return self._clean(_to_plain(value, 0), hint, 0, objects=False)

    def _clean(self, node: Any, hint: str, depth: int, *, objects: bool) -> Any:
        """Redact the data in ``node``; containers are rebuilt, never modified.

        Other objects are kept as they are, or, with ``objects`` (for copies only),
        redacted in place so that they keep their classes.
        """
        if depth > _MAX_NESTING:
            raise RedactionError("value too deeply nested")
        if node is None or isinstance(node, bool | float | _ATOMIC):
            return node
        if isinstance(node, str | int | bytes | bytearray):
            return self.redactor.redact_value(node, hint)
        if isinstance(node, Mapping):
            # Plain entries are redacted together, so that sensitive field names apply.
            data = {str(key): item for key, item in node.items() if _is_data(item, 0)}
            clean = self.redactor.redact_value(_to_plain(data, 0), hint) if data else {}
            return {
                key: clean[str(key)]
                if str(key) in clean
                else self._clean(item, str(key), depth + 1, objects=objects)
                for key, item in node.items()
            }
        if isinstance(node, list | tuple):
            items = [self._clean(item, hint, depth + 1, objects=objects) for item in node]
            return tuple(items) if isinstance(node, tuple) else items
        if not objects or _is_lazy(node):
            return node
        fields = getattr(node, "__dict__", None)
        if not isinstance(fields, dict):
            raise RedactionError("unsupported object in a response")
        _clean_fields(self, fields, depth)
        for slot in ("__pydantic_extra__", "__pydantic_private__"):
            extra = getattr(node, slot, None)
            if isinstance(extra, dict):
                _clean_fields(self, extra, depth)
        return node


def _clean_fields(logger: CaviardLogger, fields: dict[str, Any], depth: int) -> None:
    for name, value in list(fields.items()):
        fields[name] = logger._clean(value, name.lstrip("_"), depth + 1, objects=True)


def _is_data(value: Any, depth: int) -> bool:
    """True for JSON-like values: what can be redacted without changing a type."""
    if depth > _MAX_NESTING:
        return False
    if value is None or isinstance(value, str | int | float):
        return True
    if isinstance(value, list | tuple):
        return all(_is_data(item, depth + 1) for item in value)
    if isinstance(value, Mapping):
        return all(_is_data(item, depth + 1) for item in value.values())
    return False


def _is_lazy(value: Any) -> bool:
    """Coroutines, generators and streams: they hold no text until consumed."""
    return (
        inspect.isawaitable(value)
        or inspect.isgenerator(value)
        or inspect.isasyncgen(value)
        or hasattr(value, "__next__")
        or hasattr(value, "__anext__")
    )


def _to_plain(value: Any, depth: int) -> Any:
    """JSON-like copy of ``value``: model objects are dumped, other objects become text."""
    if depth > _MAX_NESTING:
        return QUARANTINED
    if value is None or isinstance(value, str | int | float | bytes | bytearray):
        return value
    if isinstance(value, Mapping):
        return {str(key): _to_plain(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_to_plain(item, depth + 1) for item in value]
    try:
        dump = getattr(value, "model_dump", None)
        return _to_plain(dump(), depth + 1) if callable(dump) else str(value)
    except Exception:
        return QUARANTINED


def _quarantined_details(kwargs: Mapping[str, Any]) -> dict[str, Any]:
    """Every text becomes QUARANTINED; numbers, flags and LiteLLM objects are kept."""
    details = dict(kwargs)
    for key, value in kwargs.items():
        if key in _PASSTHROUGH_KEYS:
            continue
        try:
            details[key] = _placeholder(value, 0)
        except Exception:
            details[key] = QUARANTINED
    return details


def _placeholder(node: Any, depth: int) -> Any:
    if depth > _MAX_NESTING or isinstance(node, str | bytes | bytearray):
        return QUARANTINED
    if node is None or isinstance(node, bool | float):
        return node
    if isinstance(node, int):
        return node if -_INT_LIMIT < node < _INT_LIMIT else QUARANTINED
    if isinstance(node, Mapping):
        return {key: _placeholder(item, depth + 1) for key, item in node.items()}
    if isinstance(node, list | tuple):
        return [_placeholder(item, depth + 1) for item in node]
    return QUARANTINED if hasattr(node, "model_dump") else node
