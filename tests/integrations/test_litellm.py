"""LiteLLM callback: every logger sees redacted data, the application keeps the real data.

LiteLLM's ``mock_response`` runs the whole logging pipeline without any network call.
"""

from __future__ import annotations

import asyncio
import copy
import datetime
import json
import time
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from caviard import OnError
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


def _visible(kwargs: dict[str, Any]) -> dict[str, Any]:
    # The exception object is passed through on purpose (see the module docstring).
    return {key: value for key, value in kwargs.items() if key != "exception"}


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


def test_async_completion_and_stream(capture: Capture, pii: dict[str, str]) -> None:
    legacy = Legacy()  # makes LiteLLM also run its sync handler, in a thread
    litellm.callbacks = [CaviardLogger(redactor=make_redactor()), capture]
    litellm.success_callback = [legacy]
    messages = [{"role": "user", "content": f"Mon téléphone : {pii['phone']}"}]
    answer = f"Nous vous écrirons à {pii['email']}."

    async def scenario() -> str:
        response = await litellm.acompletion(model=MODEL, messages=messages, mock_response=answer)
        assert response.choices[0].message.content == answer
        stream = await litellm.acompletion(
            model=MODEL, messages=messages, mock_response=answer, stream=True
        )
        text = "".join([chunk.choices[0].delta.content or "" async for chunk in stream])
        await _async_wait_for(lambda: capture.count("async_success") >= 2)
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
    assert details["exception"] is error
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
