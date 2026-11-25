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

Not covered: LiteLLM hands the raw request to the ``log_pre_api_call`` and
``log_post_api_call`` hooks of every logger, before any redaction hook can run
(and the LiteLLM proxy hands raw requests and responses to its own hooks). A
logger that records data there, such as LiteLLM's Langfuse OpenTelemetry logger
with trace metadata, records it unredacted: CaviardLogger warns once when such a
logger is registered. For LiteLLM's OpenTelemetry loggers, export through
``caviard.otel.RedactingSpanExporter`` instead (``OpenTelemetryConfig(exporter=...)``),
which covers every span whatever the hook.

On failure, the callbacks receive a copy of the exception, of the same class:
its arguments and attributes are redacted, its traceback is not kept (the frames
hold local variables, which some loggers collect) and the redacted traceback
text is attached as a note; chained exceptions are copied the same way. The
exception raised to the application is not modified. LiteLLM quotes the start
of the messages in some exception texts: set ``litellm.redact_messages_in_exceptions
= True`` too, for the logs of the application itself.

Left unchanged on purpose: Python objects other than plain data in the
parameters and in the exception (clients, callables, the HTTP response, whose
headers and status code the loggers read) and ``standard_callback_dynamic_params``,
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
import re
import threading
import traceback
import uuid
import weakref
from collections import OrderedDict
from collections.abc import Callable, Mapping
from importlib import metadata
from pathlib import Path
from typing import Any

try:
    from litellm.integrations.custom_logger import CustomLogger
except ImportError as exc:  # pragma: no cover - depends on the environment
    raise ImportError("this integration needs LiteLLM: pip install 'caviard[litellm]'") from exc

from caviard.core import entities as E
from caviard.core.errors import RedactionError, warn
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
_MAX_CHAIN = 8  # chained exceptions (__cause__, __context__) copied for the loggers
_INT_LIMIT = 100_000_000  # smaller integers cannot hold an identifier
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_REDACTED_FLAG = "_caviard_redacted"
# Before 1.87.4, LiteLLM ran the async and sync loggers of a streamed async call at the
# same time: an async logger could read the state while the sync thread wrote fresh,
# unredacted payloads into it.
_MIN_LITELLM = (1, 87, 4)
# Logger hooks that LiteLLM calls with raw data, before any redaction hook can run.
_RAW_HOOKS = ("log_pre_api_call", "log_post_api_call")
_ROUTING_MODULES = "litellm.router_strategy."  # routing helpers read deployment ids only
# Streamed async calls whose state CaviardLogger can find again (weak references).
_MAX_STREAMED = 1_024
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
        self._loggers_checked = False
        self._streamed: OrderedDict[str, weakref.ref[_StreamedState]] = OrderedDict()
        self._streamed_lock = threading.Lock()
        version = _litellm_version()
        if version is not None and version < _MIN_LITELLM:
            warn(
                f"LiteLLM {'.'.join(map(str, version))} runs the async and sync loggers of "
                "streamed calls at the same time, so a logger may see unredacted data: "
                "upgrade to LiteLLM 1.87.4 or later"
            )

    @classmethod
    def from_policy(cls, path: str | Path, **kwargs: Any) -> CaviardLogger:
        """Build the callback from a policy file."""
        return cls(Policy.load(path), **kwargs)

    # Before the request: nothing can be redacted yet, the other loggers are checked once.

    def log_pre_api_call(self, model: Any, messages: Any, kwargs: Any) -> None:
        if self._loggers_checked:
            return
        self._loggers_checked = True
        names = _raw_data_loggers()
        if names:
            warn(
                f"LiteLLM hands the raw request to the log_pre_api_call and "
                f"log_post_api_call hooks of {', '.join(names)}, before CaviardLogger can "
                "redact it: check that they record nothing there, or export their spans "
                "through caviard.otel.RedactingSpanExporter"
            )

    # Success: LiteLLM passes what these hooks return to every logging callback.

    def logging_hook(
        self, kwargs: dict[str, Any], result: Any, call_type: str
    ) -> tuple[dict[str, Any], Any]:
        streamed = self._streamed_state(kwargs)
        if streamed is not None:
            self._redact_state(streamed)  # what the async callbacks received
        return self._redact_state(kwargs), self._response(result)

    async def async_logging_hook(
        self, kwargs: dict[str, Any], result: Any, call_type: str
    ) -> tuple[dict[str, Any], Any]:
        return self._streamed_copy(self._redact_state(kwargs)), self._response(result)

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
        callbacks received; the next hook call redacts them again (see
        ``_streamed_copy`` for the LiteLLM releases that hand it a copy).
        """
        if not isinstance(kwargs, Mapping):
            return kwargs
        snapshot = dict(kwargs)  # one atomic copy: that thread may write meanwhile
        details = self._details(snapshot)
        if isinstance(kwargs, dict):
            for key in snapshot.keys() - details.keys():
                kwargs.pop(key, None)  # a key that was itself redacted
            kwargs.update(details)
            return kwargs
        return details

    def _streamed_copy(self, state: Any) -> Any:
        """The redacted state of a streamed async call, as a dictionary found again later.

        LiteLLM's sync handler runs after the async callbacks, which receive this
        dictionary, and writes the assembled response into it; a logger may keep the
        dictionary and read it later. Since LiteLLM 1.108, that handler hands
        ``logging_hook`` a copy of it: the dictionary is redacted again then. It is
        weakly referenced, so it is never kept alive for that.
        """
        if not isinstance(state, dict) or state.get("stream") is not True:
            return state
        call_id = state.get("litellm_call_id")
        if not isinstance(call_id, str):
            return state
        streamed = state if isinstance(state, _StreamedState) else _StreamedState(state)
        with self._streamed_lock:
            self._streamed.pop(call_id, None)
            self._streamed[call_id] = weakref.ref(streamed)
            # Calls whose state LiteLLM dropped go first; this one stays.
            oldest = iter(self._streamed.values())
            while len(self._streamed) > _MAX_STREAMED or next(oldest)() is None:
                self._streamed.popitem(last=False)
                oldest = iter(self._streamed.values())
        return streamed

    def _streamed_state(self, kwargs: Any) -> _StreamedState | None:
        """The state of the same streamed call, when ``kwargs`` is another dictionary."""
        if not isinstance(kwargs, Mapping):
            return None
        call_id = kwargs.get("litellm_call_id")
        if not isinstance(call_id, str):
            return None
        with self._streamed_lock:
            reference = self._streamed.pop(call_id, None)
        streamed = reference() if reference is not None else None
        return None if streamed is None or streamed is kwargs else streamed

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
        details = {key: value for key, value in kwargs.items() if key not in others}
        details.update(self._clean(others, "", 0, objects=False))
        for key in _CONTENT_KEYS & details.keys():
            value = details[key]
            if value is not None and not _is_lazy(value):
                details[key] = self._plain(value, key)
        for key in _RESPONSE_KEYS & details.keys():
            details[key] = self._response(details[key])
        error = details.get("exception")
        if isinstance(error, BaseException):
            details["exception"] = self._exception(error)
        return details

    def _exception(self, error: BaseException) -> BaseException:
        """Copy of the exception for the loggers, of the same class, with its texts redacted.

        LiteLLM's exception texts can quote the start of the messages, and loggers such
        as LiteLLM's OpenTelemetry one record the exception object itself.
        """
        if getattr(error, _REDACTED_FLAG, False):
            return error  # already a copy made here: the failure callbacks can run twice
        trace = "".join(traceback.format_exception(error))
        # Texts and plain data are redacted; objects such as the HTTP response are kept.
        clone = _copy_exception(
            error, lambda name, value: self._clean(value, name, 0, objects=False)
        )
        clone.add_note(self.redactor.redact_value(trace))  # the stack, as redacted text
        setattr(clone, _REDACTED_FLAG, True)
        return clone

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
        if node is None or isinstance(node, bool | _ATOMIC):
            return node
        if isinstance(node, str | int | float | bytes | bytearray):
            return self.redactor.redact_value(node, hint)
        if isinstance(node, Mapping):
            # Plain entries are redacted together, so that sensitive field names apply;
            # they come back with their keys redacted too.
            data = {str(key): item for key, item in node.items() if _is_data(item, 0)}
            result: dict[Any, Any] = (
                dict(self.redactor.redact_value(_to_plain(data, 0), hint)) if data else {}
            )
            for key, item in node.items():
                if str(key) not in data:
                    clean = self._clean(item, str(key), depth + 1, objects=objects)
                    result[self.redactor.redact_key(key)] = clean
            return result
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


class _StreamedState(dict[str, Any]):
    """LiteLLM's logging state of a streamed async call: a dictionary that can be
    weakly referenced."""

    __slots__ = ("__weakref__",)


def _litellm_version() -> tuple[int, ...] | None:
    """Release numbers of the installed LiteLLM, such as (1, 87, 4)."""
    try:
        text = metadata.version("litellm")
    except metadata.PackageNotFoundError:  # pragma: no cover - imported from a source tree
        return None
    numbers: list[int] = []
    for part in text.split(".")[:3]:
        digits = re.match(r"[0-9]+", part)
        if digits is None:
            break
        numbers.append(int(digits.group()))
    return tuple(numbers)


def _raw_data_loggers() -> list[str]:
    """Names of the registered loggers that LiteLLM hands raw data to: loggers that
    implement ``log_pre_api_call`` or ``log_post_api_call``, legacy input callbacks
    (names such as ``"sentry"``) and plain functions."""
    import litellm

    names: set[str] = set()
    for callback in list(getattr(litellm, "input_callback", None) or ()):
        if isinstance(callback, CaviardLogger):
            continue
        if isinstance(callback, CustomLogger):
            kind = type(callback)
            if kind.__module__.startswith(_ROUTING_MODULES):
                continue
            base = CustomLogger
            if any(getattr(kind, hook, None) is not getattr(base, hook) for hook in _RAW_HOOKS):
                names.add(kind.__name__)
        elif isinstance(callback, str):
            names.add(repr(callback))
        elif callable(callback):
            names.add(getattr(callback, "__name__", type(callback).__name__))
    return sorted(names)


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
        result: dict[Any, Any] = {}
        for key, item in node.items():
            # Keys are texts too: only plain identifiers ("role", "total_tokens") are kept.
            name = key if _plain_identifier(key) else QUARANTINED
            if name in result:
                name = f"{QUARANTINED}#{len(result) + 1}"
            result[name] = _placeholder(item, depth + 1)
        return result
    if isinstance(node, list | tuple):
        return [_placeholder(item, depth + 1) for item in node]
    if isinstance(node, BaseException):
        return _copy_exception(node, lambda name, value: _placeholder(value, depth + 1))
    return QUARANTINED if hasattr(node, "model_dump") else node


def _plain_identifier(key: Any) -> bool:
    """Schema-like keys; e-mail addresses, numbers and free text are not."""
    return (
        isinstance(key, str)
        and _IDENTIFIER.fullmatch(key) is not None
        and sum(char.isdigit() for char in key) < 4
    )


def _copy_exception(
    error: BaseException, convert: Callable[[str, Any], Any], depth: int = 0
) -> BaseException:
    """Same-class copy of ``error`` whose arguments and attributes go through ``convert``.

    The traceback is not kept: its frames hold local variables, which some loggers
    collect. Chained exceptions are copied the same way.
    """
    try:
        clone = type(error).__new__(type(error))
        clone.args = tuple(convert("exception", arg) for arg in error.args)
        for name, value in vars(error).items():
            setattr(clone, name, convert(name, value))
    except Exception:
        clone = Exception(QUARANTINED)
    for link in ("__cause__", "__context__"):
        chained = getattr(error, link, None)
        if isinstance(chained, BaseException) and depth < _MAX_CHAIN:
            setattr(clone, link, _copy_exception(chained, convert, depth + 1))
        else:
            setattr(clone, link, None)
    clone.__suppress_context__ = error.__suppress_context__
    return clone
