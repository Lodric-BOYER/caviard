"""LiteLLM callback: every logger sees redacted data, the application keeps the real data.

LiteLLM's ``mock_response`` runs the whole logging pipeline without any network call.
"""

from __future__ import annotations

import asyncio
import copy
import datetime
import gc
import json
import time
import traceback
import warnings
import weakref
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from caviard import CaviardWarning, OnError
from helpers import dump, exploding_redactor, leaked, make_redactor

pytestmark = [
    pytest.mark.integration,
    # Emitted by LiteLLM's own pydantic models, not by caviard.
    pytest.mark.filterwarnings("ignore:.*ReadOnly. qualifier:UserWarning"),
]
litellm = pytest.importorskip("litellm")
integration = pytest.importorskip("caviard.integrations.litellm")

MODEL = "gpt-4o-mini"
QUARANTINED = integration.QUARANTINED
CaviardLogger = integration.CaviardLogger


def _tokenizer_loads() -> bool:
    try:
        from litellm.litellm_core_utils import default_encoding  # noqa: F401
    except Exception:
        return False
    return True


# LiteLLM counts streamed tokens with tiktoken. Its Windows wheels (1.106) ship tokenizer
# files with Windows line endings: tiktoken rejects them and downloads them again, which
# fails offline or behind a TLS-inspecting proxy. Without a tokenizer there is no stream.
needs_tokenizer = pytest.mark.skipif(
    not _tokenizer_loads(), reason="LiteLLM cannot load its tokenizer on this machine"
)


def _visible(kwargs: dict[str, Any]) -> dict[str, Any]:
    """What a logger can read; the exception is rendered as loggers render it."""
    visible = dict(kwargs)
    error = visible.get("exception")
    if isinstance(error, BaseException):
        visible["exception"] = [repr(error), *traceback.format_exception(error)]
    return visible


class Capture(litellm.integrations.custom_logger.CustomLogger):
    """Serialises what each callback receives, at the moment it receives it."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[tuple[str, dict[str, Any], Any, str]] = []

    def _record(self, kind: str, kwargs: dict[str, Any], response_obj: Any) -> None:
        self.events.append((kind, kwargs, response_obj, dump([_visible(kwargs), response_obj])))

    def first(self, kind: str) -> tuple[str, dict[str, Any], Any, str]:
        return next(event for event in self.events if event[0] == kind)

    def count(self, kind: str) -> int:
        return sum(event[0] == kind for event in self.events)

    def log_success_event(self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any):
        self._record("success", kwargs, response_obj)

    async def async_log_success_event(
        self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
    ):
        self._record("async_success", kwargs, response_obj)

    def log_failure_event(self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any):
        self._record("failure", kwargs, response_obj)

    async def async_log_failure_event(
        self, kwargs: Any, response_obj: Any, start_time: Any, end_time: Any
    ):
        self._record("async_failure", kwargs, response_obj)


class Legacy:
    """A plain function callback, the oldest way to plug a logger into LiteLLM."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    def __call__(self, kwargs: Any, completion_response: Any, start_time: Any, end_time: Any):
        self.seen.append(dump([_visible(kwargs), completion_response]))


@pytest.fixture
def capture(monkeypatch: pytest.MonkeyPatch) -> Capture:
    """A capturing logger; LiteLLM's global callback lists are restored afterwards."""
    for name in (
        "callbacks",
        "success_callback",
        "failure_callback",
        "_async_success_callback",
        "_async_failure_callback",
        "input_callback",
        "service_callback",
    ):
        monkeypatch.setattr(litellm, name, [], raising=False)
    return Capture()


def _is_clean(state: dict[str, Any], pii: dict[str, str]) -> bool:
    try:
        return not leaked(dump(_visible(state)), pii.values())
    except RuntimeError:  # changed by a LiteLLM thread while being read
        return False


def _wait_for(condition: Callable[[], bool], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("LiteLLM did not call the logging callbacks in time")
        time.sleep(0.02)


async def _async_wait_for(condition: Callable[[], bool], timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("LiteLLM did not call the logging callbacks in time")
        await asyncio.sleep(0.02)


def test_sync_completion(capture: Capture, pii: dict[str, str]) -> None:
    caviard = CaviardLogger(redactor=make_redactor())
    legacy = Legacy()
    litellm.callbacks = [caviard, capture]
    litellm.success_callback = [legacy]
    messages = [
        {"role": "system", "content": "Tu es l'assistant du service client."},
        {"role": "user", "content": f"Mon IBAN est {pii['iban']}, mon mail {pii['email']}"},
    ]
    original = copy.deepcopy(messages)
    answer = f"C'est noté, je vous rappelle au {pii['phone']}."

    response = litellm.completion(
        model=MODEL,
        messages=messages,
        mock_response=answer,
        user=pii["email"],
        metadata={"trace_user_id": pii["email"], "ticket": "T-1042"},
    )

    # The application keeps the real data.
    assert response.choices[0].message.content == answer
    assert messages == original
    _wait_for(lambda: capture.count("success") == 1 and len(legacy.seen) == 1)
    _, kwargs, response_obj, seen = capture.first("success")
    assert leaked(seen, pii.values()) == []
    assert leaked(legacy.seen[0], pii.values()) == []
    # LiteLLM's logging state stays redacted for later reads too.
    assert leaked(dump(_visible(kwargs)), pii.values()) == []
    # What is not personal stays readable.
    payload = kwargs["standard_logging_object"]
    assert payload["model"] == MODEL
    assert payload["total_tokens"] > 0
    assert payload["response_cost"] > 0
    assert kwargs["messages"][1]["role"] == "user"
    assert "[IBAN]" in kwargs["messages"][1]["content"]
    assert kwargs["litellm_params"]["metadata"]["ticket"] == "T-1042"
    assert response_obj.choices[0].message.content.startswith("C'est noté, je vous rappelle au [")
    assert caviard.redactor.stats.snapshot()["EMAIL"] >= 1


@needs_tokenizer
def test_sync_stream(capture: Capture, pii: dict[str, str]) -> None:
    litellm.callbacks = [CaviardLogger(redactor=make_redactor()), capture]
    answer = f"Votre conseiller vous écrira à {pii['email']}."

    stream = litellm.completion(
        model=MODEL,
        messages=[{"role": "user", "content": f"Mon NIR : {pii['nir']}"}],
        mock_response=answer,
        stream=True,
    )
    text = "".join(chunk.choices[0].delta.content or "" for chunk in stream)

    assert text == answer
    _wait_for(lambda: capture.count("success") >= 1)
    for _, _, _, seen in capture.events:
        assert leaked(seen, pii.values()) == []
    _, kwargs, _, _ = capture.first("success")
    streamed = kwargs["complete_streaming_response"]
    assert isinstance(streamed, litellm.ModelResponse)
    assert "[EMAIL:" in streamed.choices[0].message.content


@pytest.mark.parametrize("stream", [pytest.param(True, marks=needs_tokenizer), False])
def test_async_completion(capture: Capture, pii: dict[str, str], stream: bool) -> None:
    legacy = Legacy()  # makes LiteLLM also run its sync handler, in a thread
    litellm.callbacks = [CaviardLogger(redactor=make_redactor()), capture]
    litellm.success_callback = [legacy]
    messages = [{"role": "user", "content": f"Mon téléphone : {pii['phone']}"}]
    answer = f"Nous vous écrirons à {pii['email']}."

    async def scenario() -> str:
        if stream:
            response = await litellm.acompletion(
                model=MODEL, messages=messages, mock_response=answer, stream=True
            )
            text = "".join([chunk.choices[0].delta.content or "" async for chunk in response])
        else:
            response = await litellm.acompletion(
                model=MODEL, messages=messages, mock_response=answer
            )
            text = response.choices[0].message.content
        await _async_wait_for(lambda: capture.count("async_success") >= 1)
        return text

    assert asyncio.run(scenario()) == answer
    for _, _, _, seen in capture.events:
        assert leaked(seen, pii.values()) == []
    # LiteLLM's sync handler thread writes fresh payloads into the state the async
    # callbacks received; the next hook call redacts them again.
    for _, kwargs, _, _ in capture.events:
        _wait_for(lambda kwargs=kwargs: _is_clean(kwargs, pii))
    for seen in legacy.seen:
        assert leaked(seen, pii.values()) == []


def _async_hooks(caviard: Any, states: list[dict[str, Any]]) -> list[Any]:
    """What the async callbacks receive for each logging state."""

    async def run() -> list[Any]:
        results = []
        for state in states:
            redacted, _ = await caviard.async_logging_hook(state, None, "acompletion")
            results.append(redacted)
        return results

    return asyncio.run(run())


def test_streamed_async_state_is_redacted_again(pii: dict[str, str]) -> None:
    """LiteLLM 1.108 and later: once the async callbacks ran, the sync handler writes the
    assembled response into the state they received, then hands the sync hook a copy."""
    caviard = CaviardLogger(redactor=make_redactor())
    original: dict[str, Any] = {
        "litellm_call_id": "call-1",
        "stream": True,
        "messages": [{"role": "user", "content": f"Mon mail : {pii['email']}"}],
    }

    [state] = _async_hooks(caviard, [original])

    assert state == original
    assert _is_clean(state, pii)
    assert _is_clean(original, pii)
    state["complete_streaming_response"] = litellm.ModelResponse(
        choices=[{"message": {"role": "assistant", "content": f"Rappel au {pii['phone']}"}}]
    )
    copied = {**state, "standard_logging_object": {"response": f"Rappel au {pii['phone']}"}}

    redacted, _ = caviard.logging_hook(copied, None, "acompletion")

    assert redacted is copied
    assert _is_clean(copied, pii)
    assert _is_clean(state, pii)
    message = state["complete_streaming_response"].choices[0].message
    assert message.content.startswith("Rappel au [")
    assert not caviard._streamed  # forgotten once redacted again


def test_streamed_state_handed_back_to_the_sync_hook(pii: dict[str, str]) -> None:
    """LiteLLM before 1.108 hands the sync hook the state itself."""
    caviard = CaviardLogger(redactor=make_redactor())
    [state] = _async_hooks(caviard, [{"litellm_call_id": "call-2", "stream": True}])
    state["complete_streaming_response"] = f"Rappel au {pii['phone']}"

    redacted, _ = caviard.logging_hook(state, None, "acompletion")

    assert redacted is state
    assert _is_clean(state, pii)
    assert not caviard._streamed


def test_streamed_states_are_never_kept_alive() -> None:
    caviard = CaviardLogger(redactor=make_redactor())
    plain = {"litellm_call_id": "plain", "stream": False}
    assert _async_hooks(caviard, [plain]) == [plain]
    assert not caviard._streamed  # only streamed calls get a sync handler run afterwards

    count = integration._MAX_STREAMED + 3
    states = _async_hooks(
        caviard, [{"litellm_call_id": f"call-{n}", "stream": True} for n in range(count)]
    )

    assert len(caviard._streamed) == integration._MAX_STREAMED
    assert "call-0" not in caviard._streamed  # the oldest go first
    last = weakref.ref(states[-1])
    del states
    gc.collect()
    assert last() is None  # weakly referenced: LiteLLM alone keeps a state alive
    caviard.logging_hook({"litellm_call_id": f"call-{count - 1}"}, None, "acompletion")
    assert f"call-{count - 1}" not in caviard._streamed
    kept = _async_hooks(caviard, [{"litellm_call_id": "next", "stream": True}])
    assert list(caviard._streamed) == ["next"]  # the dropped states are forgotten
    assert caviard._streamed["next"]() is kept[0]


def test_sync_failure(capture: Capture, pii: dict[str, str]) -> None:
    litellm.callbacks = [CaviardLogger(redactor=make_redactor()), capture]

    with pytest.raises(litellm.exceptions.InternalServerError):
        litellm.completion(
            model=MODEL,
            messages=[{"role": "user", "content": f"Virement depuis {pii['iban']}"}],
            mock_response=Exception(f"upstream refused {pii['email']}"),
        )

    _wait_for(lambda: capture.count("failure") == 1)
    _, kwargs, _, seen = capture.first("failure")
    assert leaked(seen, pii.values()) == []
    payload = kwargs["standard_logging_object"]
    assert payload["status"] == "failure"
    assert "[EMAIL:" in payload["error_str"]
    assert "[EMAIL:" in kwargs["traceback_exception"]
    # Loggers that record the exception itself (LiteLLM's OpenTelemetry one does) see a
    # copy of the same class, with its status code and a redacted text.
    error = kwargs["exception"]
    assert isinstance(error, litellm.exceptions.InternalServerError)
    assert error.status_code == 500
    assert "[EMAIL:" in str(error)
    assert error.__traceback__ is None  # frames hold local variables
    assert "Traceback (most recent call last)" in error.__notes__[-1]


def test_async_failure(capture: Capture, pii: dict[str, str]) -> None:
    litellm.callbacks = [CaviardLogger(redactor=make_redactor()), capture]

    async def scenario() -> None:
        with pytest.raises(litellm.exceptions.InternalServerError):
            await litellm.acompletion(
                model=MODEL,
                messages=[{"role": "user", "content": f"Mon NIR : {pii['nir']}"}],
                mock_response=Exception(f"upstream refused {pii['phone']}"),
            )
        await _async_wait_for(lambda: capture.count("async_failure") == 1)

    asyncio.run(scenario())
    _, kwargs, _, seen = capture.first("async_failure")
    assert leaked(seen, pii.values()) == []
    assert kwargs["standard_logging_object"]["status"] == "failure"


def test_redaction_failure_quarantines_the_call(capture: Capture, pii: dict[str, str]) -> None:
    caviard = CaviardLogger(redactor=exploding_redactor())
    litellm.callbacks = [caviard, capture]
    answer = f"Rappel au {pii['phone']}"

    response = litellm.completion(
        model=MODEL,
        messages=[{"role": "user", "content": f"Mon mail : {pii['email']}"}],
        mock_response=answer,
    )

    assert response.choices[0].message.content == answer
    _wait_for(lambda: capture.count("success") == 1)
    _, kwargs, response_obj, seen = capture.first("success")
    assert leaked(seen, pii.values()) == []
    assert response_obj == QUARANTINED
    assert kwargs["messages"] == [{"role": QUARANTINED, "content": QUARANTINED}]
    assert kwargs["standard_logging_object"]["total_tokens"] > 0  # numbers are kept
    assert caviard.redactor.stats.snapshot()["QUARANTINED"] >= 2


def test_logging_state_keeps_litellm_objects(pii: dict[str, str]) -> None:
    caviard = CaviardLogger(redactor=make_redactor())
    started = datetime.datetime(2026, 10, 18, 9, 30, tzinfo=datetime.UTC)
    error = ValueError("the exception object is passed through")

    def token_provider() -> str:
        return "token"

    history = litellm.Message(role="assistant", content=f"Je note {pii['email']}")
    state: dict[str, Any] = {
        "model": MODEL,
        "start_time": started,
        "exception": error,
        "api_key": pii["api_key"],
        "user": pii["email"],
        "standard_callback_dynamic_params": {"langfuse_secret_key": "sk-lf-kept-as-is"},
        "messages": [{"role": "user", "content": pii["phone"]}, history],
        "original_response": json.dumps({"choices": [{"text": f"IBAN {pii['iban']}"}]}),
        "additional_args": {"complete_input_dict": {"prompt": f"NIR {pii['nir']}"}},
        "traceback_exception": f"Traceback (most recent call last):\nValueError: {pii['email']}",
        "litellm_params": {
            "azure_ad_token_provider": token_provider,
            "api_base": "https://api.openai.com/v1",
            "metadata": {
                "headers": {"authorization": f"Bearer {pii['api_key']}"},
                "customer": {"phone": pii["phone"]},
            },
        },
    }

    details, _ = caviard.logging_hook(state, None, "completion")

    assert details is state  # redacted in place, values replaced
    assert leaked(dump(_visible(details)), pii.values()) == []
    assert details["model"] == MODEL
    assert details["start_time"] is started
    # Loggers get a copy of the exception: same class, same text when it holds no data.
    assert type(details["exception"]) is ValueError
    assert details["exception"] is not error
    assert str(details["exception"]) == str(error)
    assert details["api_key"] == "[REDACTED]"
    assert details["standard_callback_dynamic_params"] == {
        "langfuse_secret_key": "sk-lf-kept-as-is"
    }
    params = details["litellm_params"]
    assert params["azure_ad_token_provider"] is token_provider
    assert params["api_base"] == "https://api.openai.com/v1"
    assert params["metadata"]["headers"]["authorization"] == "[REDACTED]"
    assert details["messages"][1]["role"] == "assistant"
    assert history.content.endswith(pii["email"])  # the application's object is untouched


def test_response_shapes(pii: dict[str, str]) -> None:
    caviard = CaviardLogger(redactor=make_redactor())

    def redacted(result: Any) -> Any:
        return caviard.logging_hook({}, result, "completion")[1]

    assert redacted(None) is None
    assert redacted(7) == 7
    assert redacted(f"IBAN {pii['iban']}") == "IBAN [IBAN]"
    assert redacted({"text": f"IBAN {pii['iban']}"}) == {"text": "IBAN [IBAN]"}
    assert redacted(iter([pii["email"]])) == QUARANTINED
    embedding = litellm.EmbeddingResponse(model=MODEL, data=[{"embedding": [0.1, 0.2]}])
    assert redacted(embedding) is embedding


def test_model_response_copy_keeps_its_classes(pii: dict[str, str]) -> None:
    caviard = CaviardLogger(redactor=make_redactor())
    arguments = json.dumps({"iban": pii["iban"], "amount": 120, "note": pii["email"]})
    response = litellm.ModelResponse(
        model=MODEL,
        choices=[
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "reasoning_content": f"Le client {pii['email']} demande un virement",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "send_transfer", "arguments": arguments},
                        }
                    ],
                },
            }
        ],
    )
    before = response.model_dump()

    _, copy_ = caviard.logging_hook({}, response, "completion")

    assert response.model_dump() == before  # the application's response is untouched
    assert type(copy_) is type(response)
    assert leaked(dump(copy_), pii.values()) == []
    message = copy_.choices[0].message
    call = message.tool_calls[0]
    assert call.function.name == "send_transfer"
    assert json.loads(call.function.arguments)["iban"] == "[REDACTED]"
    assert json.loads(call.function.arguments)["amount"] == 120
    assert message.reasoning_content.startswith("Le client [EMAIL:")


def test_unsupported_response_object_is_quarantined(pii: dict[str, str]) -> None:
    class Opaque:
        __slots__ = ("text",)

        def __init__(self, text: str) -> None:
            self.text = text

    caviard = CaviardLogger(redactor=make_redactor())
    assert caviard.logging_hook({}, Opaque(pii["email"]), "completion")[1] == QUARANTINED
    assert caviard.redactor.stats.snapshot() == {"QUARANTINED": 1}


def test_edge_cases(pii: dict[str, str]) -> None:
    caviard = CaviardLogger(redactor=make_redactor())
    # Not LiteLLM's logging dictionary: left alone.
    caviard.log_failure_event(None, None, None, None)
    # A read-only mapping is redacted into a new dictionary.
    details, _ = caviard.logging_hook(MappingProxyType({"user": pii["email"]}), None, "completion")
    assert details["user"].startswith("[EMAIL:")
    # Lazy values hold no text until consumed: they are passed through.
    pending = (part for part in [pii["email"]])
    details, _ = caviard.logging_hook({"original_response": pending}, None, "completion")
    assert details["original_response"] is pending
    # Pathological nesting is quarantined, not exported.
    nested: list[Any] = [pii["email"]]
    for _ in range(80):
        nested = [nested]
    details, _ = caviard.logging_hook({"messages": nested}, None, "completion")
    assert leaked(dump(details), pii.values()) == []
    params = {"litellm_params": {"metadata": nested}}
    details, _ = caviard.logging_hook(params, None, "completion")
    assert leaked(dump(details), pii.values()) == []
    assert caviard.redactor.stats.snapshot()["QUARANTINED"] == 2


def test_from_policy(tmp_path: Path) -> None:
    path = tmp_path / "caviard.toml"
    path.write_text('version = 1\npreset = "strict"\n', encoding="utf-8")
    caviard = CaviardLogger.from_policy(path)
    assert caviard.redactor.policy.on_error is OnError.DROP


def test_failing_conversions_are_quarantined(pii: dict[str, str]) -> None:
    class Unreadable:
        def model_dump(self) -> dict[str, Any]:
            raise RuntimeError("cannot dump")

    caviard = CaviardLogger(redactor=make_redactor())
    details, _ = caviard.logging_hook({"messages": [Unreadable()]}, None, "completion")
    assert details["messages"] == [QUARANTINED]


def test_quarantine_survives_unreadable_values(pii: dict[str, str]) -> None:
    class Broken(dict):  # type: ignore[type-arg]
        def items(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("cannot iterate")

    caviard = CaviardLogger(redactor=exploding_redactor())
    state = {"metadata": Broken(note=pii["email"]), "user": pii["email"]}
    details, _ = caviard.logging_hook(state, None, "completion")
    assert details["metadata"] == QUARANTINED
    assert details["user"] == QUARANTINED


def test_mapping_keys_are_redacted(pii: dict[str, str]) -> None:
    caviard = CaviardLogger(redactor=make_redactor())
    state = {
        "litellm_params": {"metadata": {"vip": {pii["email"]: {"tier": 1}}}},
        "messages": [{"role": "user", "content": "ok", "extra": {pii["phone"]: "rappel"}}],
    }
    details, _ = caviard.logging_hook(state, None, "completion")
    assert leaked(dump(details), pii.values()) == []
    (key,) = details["litellm_params"]["metadata"]["vip"]
    assert key.startswith("[EMAIL:")
    assert details["litellm_params"]["metadata"]["vip"][key] == {"tier": 1}


def test_quarantine_covers_keys_and_exceptions(pii: dict[str, str]) -> None:
    caviard = CaviardLogger(redactor=exploding_redactor())
    try:
        raise RuntimeError(f"refused for {pii['email']}")
    except RuntimeError as exc:
        error = exc
    state = {
        "exception": error,
        "metadata": {"by_mail": {pii["email"]: 1}, "total_tokens": 12},
    }
    details, _ = caviard.logging_hook(state, None, "completion")
    assert leaked(dump(_visible(details)), pii.values()) == []
    assert details["metadata"] == {"by_mail": {QUARANTINED: 1}, "total_tokens": 12}
    assert type(details["exception"]) is RuntimeError
    assert str(details["exception"]) == QUARANTINED


@pytest.mark.parametrize(
    ("installed", "warns"), [("1.85.0", True), ("1.87.4", False), ("1.106.0", False)]
)
def test_old_litellm_versions_are_flagged(
    monkeypatch: pytest.MonkeyPatch, installed: str, warns: bool
) -> None:
    monkeypatch.setattr(integration.metadata, "version", lambda name: installed)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        CaviardLogger(redactor=make_redactor())
    messages = [str(w.message) for w in caught if issubclass(w.category, CaviardWarning)]
    if warns:
        assert messages == [
            f"LiteLLM {installed} runs the async and sync loggers of streamed calls at the "
            "same time, so a logger may see unredacted data: upgrade to LiteLLM 1.87.4 or later"
        ]
    else:
        assert messages == []


class _PreCallLogger(litellm.integrations.custom_logger.CustomLogger):
    """A logger that reads the request before it is sent."""

    def log_pre_api_call(self, model: Any, messages: Any, kwargs: Any) -> None:
        pass


def test_loggers_that_read_raw_requests_are_flagged_once(
    capture: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    caviard_logger = CaviardLogger(redactor=make_redactor())
    monkeypatch.setattr(litellm, "input_callback", [caviard_logger, capture, _PreCallLogger()])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _ in range(2):
            caviard_logger.log_pre_api_call(MODEL, [], {})
    messages = [str(w.message) for w in caught if issubclass(w.category, CaviardWarning)]
    assert messages == [
        "LiteLLM hands the raw request to the log_pre_api_call and log_post_api_call hooks "
        "of _PreCallLogger, before CaviardLogger can redact it: check that they record "
        "nothing there, or export their spans through caviard.otel.RedactingSpanExporter"
    ]


def test_plain_loggers_are_not_flagged(capture: Capture, monkeypatch: pytest.MonkeyPatch) -> None:
    caviard_logger = CaviardLogger(redactor=make_redactor())
    monkeypatch.setattr(litellm, "input_callback", [caviard_logger, capture])
    with warnings.catch_warnings():
        warnings.simplefilter("error", CaviardWarning)
        caviard_logger.log_pre_api_call(MODEL, [], {})


def test_completion_with_a_pre_call_logger_warns(
    capture: Capture, monkeypatch: pytest.MonkeyPatch, pii: dict[str, str]
) -> None:
    litellm.callbacks = [CaviardLogger(redactor=make_redactor()), capture, _PreCallLogger()]
    with pytest.warns(CaviardWarning, match="_PreCallLogger"):
        litellm.completion(
            model=MODEL,
            messages=[{"role": "user", "content": pii["email"]}],
            mock_response="ok",
        )
