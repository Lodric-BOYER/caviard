"""OpenTelemetry log exporter wrapper: bodies, attributes and events go out redacted."""

from __future__ import annotations

import json
import logging

import pytest
from opentelemetry._logs import LogRecord
from opentelemetry.exporter.otlp.proto.common._log_encoder import encode_logs
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler, ReadableLogRecord
from opentelemetry.sdk._logs.export import (
    InMemoryLogRecordExporter,
    LogRecordExportResult,
    SimpleLogRecordProcessor,
)
from opentelemetry.sdk.resources import Resource

import caviard.otel
from caviard import OnError
from caviard.otel import QUARANTINE_FLAG, QUARANTINED, RedactingLogExporter
from helpers import exploding_redactor, leaked, make_redactor

pytestmark = pytest.mark.filterwarnings(
    # Emitted by the OpenTelemetry SDK itself, which moves this handler to another package.
    "ignore:.*LoggingHandler.*:DeprecationWarning"
)
EVENT = "gen_ai.client.inference.operation.details"


def _pipeline(exporter: RedactingLogExporter) -> tuple[LoggerProvider, InMemoryLogRecordExporter]:
    """A provider exporting through ``exporter`` and, in parallel, to a raw exporter."""
    resource = Resource.create({"service.name": "agent", "deployment.owner": "ops@exemple.fr"})
    provider = LoggerProvider(resource=resource)
    provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    raw = InMemoryLogRecordExporter()
    provider.add_log_record_processor(SimpleLogRecordProcessor(raw))
    return provider, raw


@pytest.fixture
def std_logger() -> logging.Logger:
    # Not registered with logging.getLogger: no handler or filter left by other tests.
    logger = logging.Logger("tests.otel_logs", logging.INFO)
    logger.propagate = False
    return logger


def _emit(provider: LoggerProvider, logger: logging.Logger, pii: dict[str, str]) -> None:
    # A GenAI event as instrumentations emit it, then a logging record with an exception.
    messages = [{"role": "user", "content": f"Mon IBAN : {pii['iban']}"}]
    provider.get_logger("tests").emit(
        LogRecord(
            event_name=EVENT,
            body={"messages": messages, "tokens": 42},
            attributes={
                "gen_ai.request.model": "gpt-4o-mini",
                "gen_ai.input.messages": json.dumps(messages),
                "user.email": pii["email"],
            },
        )
    )
    logger.addHandler(LoggingHandler(logger_provider=provider))
    try:
        raise ValueError(f"no account for {pii['phone']}")
    except ValueError:
        logger.exception("lookup failed for %s", pii["email"], extra={"customer": pii["nir"]})


def test_exported_log_records_are_redacted_on_the_wire(
    pii: dict[str, str], std_logger: logging.Logger
) -> None:
    inner = InMemoryLogRecordExporter()
    exporter = RedactingLogExporter(inner, redactor=make_redactor())
    provider, raw = _pipeline(exporter)
    _emit(provider, std_logger, pii)

    event, record = inner.get_finished_logs()
    values = [pii["iban"], pii["email"], pii["phone"], pii["nir"], "ops@exemple.fr"]
    assert leaked(encode_logs([event, record]).SerializeToString(), values) == []
    # The originals, through the parallel processor: the data was there.
    raw_wire = encode_logs(raw.get_finished_logs()).SerializeToString()
    assert sorted(leaked(raw_wire, values)) == sorted(values)

    assert event.log_record.event_name == EVENT
    assert event.log_record.body == {
        "messages": [{"role": "user", "content": "Mon IBAN : [IBAN]"}],
        "tokens": 42,
    }
    attributes = dict(event.log_record.attributes or {})
    assert attributes["gen_ai.request.model"] == "gpt-4o-mini"
    assert attributes["user.email"] == "[REDACTED]"
    assert "[IBAN]" in attributes["gen_ai.input.messages"]

    assert str(record.log_record.body).startswith("lookup failed for [EMAIL:")
    attributes = dict(record.log_record.attributes or {})
    assert attributes["customer"] == "[FR_NIR]"
    assert attributes["exception.type"] == "ValueError"
    assert "[FR_PHONE:" in attributes["exception.message"]
    assert "[FR_PHONE:" in attributes["exception.stacktrace"]
    assert record.resource.attributes["service.name"] == "agent"
    assert str(record.resource.attributes["deployment.owner"]).startswith("[EMAIL:")
    assert event.resource is record.resource  # one redacted copy per resource
    assert exporter.counters == {"redacted": 2}


def test_bodies_of_any_type(pii: dict[str, str]) -> None:
    inner = InMemoryLogRecordExporter()
    provider, _ = _pipeline(RedactingLogExporter(inner, redactor=make_redactor()))
    logger = provider.get_logger("tests")
    for body in (None, pii["email"].encode(), [pii["email"], 3], 7):
        logger.emit(LogRecord(body=body))
    bodies = [record.log_record.body for record in inner.get_finished_logs()]
    assert bodies[0] is None
    assert bodies[1] == "[REDACTED]"
    assert bodies[2][0].startswith("[EMAIL:")
    assert bodies[2][1] == 3  # log bodies may mix types
    assert bodies[3] == 7


def test_quarantine_keeps_only_allowed_attributes(pii: dict[str, str]) -> None:
    inner = InMemoryLogRecordExporter()
    exporter = RedactingLogExporter(inner, redactor=exploding_redactor())
    provider, _ = _pipeline(exporter)
    provider.get_logger("tests").emit(
        LogRecord(
            event_name=EVENT,
            body=f"mail {pii['email']}",
            attributes={"gen_ai.request.model": "gpt-4o-mini", "note": pii["phone"]},
        )
    )
    (record,) = inner.get_finished_logs()
    log = record.log_record
    assert log.body == QUARANTINED
    assert log.event_name == QUARANTINED
    assert dict(log.attributes or {}) == {
        "gen_ai.request.model": "gpt-4o-mini",
        "note": QUARANTINED,
        QUARANTINE_FLAG: True,
    }
    assert record.resource.attributes["service.name"] == "agent"
    assert record.resource.attributes["deployment.owner"] == QUARANTINED
    assert exporter.counters == {"quarantined": 1}


def test_on_error_drop_exports_nothing(pii: dict[str, str]) -> None:
    inner = InMemoryLogRecordExporter()
    exporter = RedactingLogExporter(inner, redactor=exploding_redactor(on_error=OnError.DROP))
    record = ReadableLogRecord(LogRecord(body=pii["email"]), Resource.create({}))
    assert exporter.export([record]) is LogRecordExportResult.SUCCESS
    assert inner.get_finished_logs() == ()
    assert exporter.counters == {"dropped": 1}


def test_failed_quarantine_drops_the_record(
    pii: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    inner = InMemoryLogRecordExporter()
    exporter = RedactingLogExporter(inner, redactor=exploding_redactor())

    def fail(record: ReadableLogRecord) -> ReadableLogRecord:
        raise RuntimeError("quarantine failed")

    monkeypatch.setattr(exporter, "_quarantine", fail)
    record = ReadableLogRecord(LogRecord(body=pii["email"]), Resource.create({}))
    exporter.export([record])
    assert inner.get_finished_logs() == ()
    assert exporter.counters == {"dropped": 1}


def test_flush_and_shutdown_reach_the_wrapped_exporter() -> None:
    inner = InMemoryLogRecordExporter()
    exporter = RedactingLogExporter(inner, redactor=make_redactor())
    assert exporter.force_flush() is True
    exporter.shutdown()
    record = ReadableLogRecord(LogRecord(body="after shutdown"), Resource.create({}))
    assert exporter.export([record]) is LogRecordExportResult.FAILURE


def test_old_sdk_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(caviard.otel, "_LOGS", False)
    with pytest.raises(ImportError, match=r"1\.39"):
        RedactingLogExporter(InMemoryLogRecordExporter())


def test_scope_attributes_are_redacted(pii: dict[str, str]) -> None:
    inner = InMemoryLogRecordExporter()
    provider, _ = _pipeline(RedactingLogExporter(inner, redactor=make_redactor()))
    logger = provider.get_logger("genai", "1.0", attributes={"scope.owner": pii["email"]})
    logger.emit(LogRecord(body="ok"))
    (record,) = inner.get_finished_logs()
    assert record.instrumentation_scope is not None
    assert record.instrumentation_scope.name == "genai"
    assert leaked(encode_logs([record]).SerializeToString(), pii.values()) == []
