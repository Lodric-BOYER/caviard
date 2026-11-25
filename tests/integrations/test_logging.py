"""Standard logging filter and structlog processor."""

from __future__ import annotations

import io
import logging
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

import pytest
from faker import Faker

from caviard import CaviardError, Policy
from caviard.integrations.logging import (
    QUARANTINED,
    RedactingFilter,
    install,
    structlog_processor,
)
from helpers import exploding_redactor, leaked, luhn_complete, make_redactor


class Keep(logging.Handler):
    """Keeps the records it receives, after its filters ran."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def logger(request: pytest.FixtureRequest) -> Iterator[logging.Logger]:
    log = logging.getLogger(f"caviard.tests.{request.node.name}")
    log.setLevel(logging.DEBUG)
    log.propagate = False
    yield log
    for handler in list(log.handlers):
        log.removeHandler(handler)


def _stream_handler(fmt: str) -> tuple[logging.Handler, io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter(fmt))
    return handler, stream


def test_message_arguments_and_extra_fields(logger: logging.Logger, pii: dict[str, str]) -> None:
    handler, stream = _stream_handler("%(message)s | %(customer)s | %(order_id)s")
    handler.addFilter(RedactingFilter(redactor=make_redactor()))
    logger.addHandler(handler)

    logger.info(
        "Client %s joignable au %s",
        pii["email"],
        pii["phone"],
        extra={"customer": f"IBAN {pii['iban']}", "order_id": 1042},
    )

    output = stream.getvalue()
    assert leaked(output, pii.values()) == []
    assert output.startswith("Client [EMAIL:")
    assert "| IBAN [IBAN] | 1042" in output


@dataclass
class _Contact:
    full_name: str
    email: str


class _Plan(Enum):
    PRO = "pro"


class _Unprintable:
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def __str__(self) -> str:
        raise ValueError(self.secret)

    __repr__ = __str__


@pytest.fixture
def keep(logger: logging.Logger) -> Keep:
    handler = Keep()
    handler.addFilter(RedactingFilter(redactor=make_redactor()))
    logger.addHandler(handler)
    return handler


def test_arguments_keep_their_structure(logger: logging.Logger, keep: Keep, fake: Faker) -> None:
    names = [fake.first_name(), fake.last_name()]
    # Printed, this is no literal (the date) and the names follow no pattern: only
    # the structure tells that the list under "full_name" is personal data.
    logger.info("profil %s", {"full_name": names, "seen": datetime(2026, 10, 18), "plan": "pro"})

    message = keep.records[0].getMessage()
    assert leaked(message, names) == []
    assert message == (
        "profil {'full_name': '[REDACTED]', "
        "'seen': 'datetime.datetime(2026, 10, 18, 0, 0)', 'plan': 'pro'}"
    )


def test_named_arguments(
    logger: logging.Logger, keep: Keep, pii: dict[str, str], fake: Faker
) -> None:
    name = fake.name()
    logger.info("%(customer_name)s au %(tel)s", {"customer_name": name, "tel": pii["phone"]})
    assert keep.records[0].getMessage() == "[REDACTED] au [REDACTED]"


def test_precision_cuts_the_placeholder(
    logger: logging.Logger, keep: Keep, pii: dict[str, str]
) -> None:
    logger.info("contact %.8s", pii["email"])
    message = keep.records[0].getMessage()
    assert message.startswith("contact [EMAIL")
    assert pii["email"][:8] not in message


def test_objects_are_printed_redacted(
    logger: logging.Logger, keep: Keep, pii: dict[str, str], fake: Faker
) -> None:
    contact = _Contact(fake.name(), pii["email"])
    logger.info("%s | %r", contact, contact)

    message = keep.records[0].getMessage()
    assert leaked(message, [contact.full_name, contact.email]) == []
    as_str, as_repr = message.split(" | ")
    assert as_str == as_repr  # "%r" adds no quotes around the redacted text
    assert as_str.startswith("_Contact(full_name='[REDACTED]', email=")


def test_placeholders_that_break_the_format(logger: logging.Logger, keep: Keep) -> None:
    card = luhn_complete("497010000000000")
    logger.info("carte %d", int(card))  # "%d" cannot print "[CARD]": the merged text is redacted
    message = keep.records[0].getMessage()
    assert message.startswith("carte [CARD")
    assert card not in message


def test_values_split_across_arguments(
    logger: logging.Logger, keep: Keep, pii: dict[str, str]
) -> None:
    local, domain = pii["email"].split("@")
    logger.info("%s@%s", local, domain)
    message = keep.records[0].getMessage()
    assert message.startswith("[EMAIL")
    assert leaked(message, [pii["email"]]) == []


def test_large_arguments_are_redacted_as_text(
    logger: logging.Logger, keep: Keep, pii: dict[str, str]
) -> None:
    logger.info("lot %s", [{"tel": pii["phone"], "mail": pii["email"]}] * 12_000)
    assert leaked(keep.records[0].getMessage(), pii.values()) == []


def test_arguments_of_every_container_kind(
    logger: logging.Logger, keep: Keep, pii: dict[str, str]
) -> None:
    deep: list[object] = []
    node = deep
    for _ in range(70):  # deeper than the walk goes: printed, then redacted as text
        child: list[object] = []
        node.append(child)
        node = child
    node.append(pii["email"])
    logger.info(
        "%s | %s | %s | %s",
        {pii["email"]},
        frozenset({("tel", pii["phone"])}),
        {_Plan.PRO: pii["iban"], ("k", 1): "ok"},
        deep,
        extra={"rows": [pii["nir"]] * 12_000},  # too many items: redacted as text
    )
    (record,) = keep.records
    assert leaked(record.getMessage(), pii.values()) == []
    assert leaked(str(record.rows), pii.values()) == []


def test_unprintable_argument_quarantines_the_record(
    logger: logging.Logger, keep: Keep, pii: dict[str, str]
) -> None:
    logger.info("objet %s", _Unprintable(pii["email"]))
    assert keep.records[0].getMessage() == QUARANTINED


def test_extra_objects_are_redacted_as_text(
    logger: logging.Logger, keep: Keep, pii: dict[str, str], fake: Faker
) -> None:
    contact = _Contact(fake.name(), pii["email"])
    logger.info(
        "rendez-vous",
        extra={"plan": _Plan.PRO, "contact": contact, "rows": [{"email": pii["email"]}]},
    )

    (record,) = keep.records
    assert record.plan == "_Plan.PRO"
    assert record.contact.startswith("_Contact(full_name='[REDACTED]'")
    assert leaked(record.contact, [contact.full_name, contact.email]) == []
    assert record.rows == [{"email": "[REDACTED]"}]


def test_exceptions_and_stacks(logger: logging.Logger, pii: dict[str, str]) -> None:
    handler, stream = _stream_handler("%(levelname)s %(message)s")
    handler.addFilter(RedactingFilter(redactor=make_redactor()))
    logger.addHandler(handler)

    try:
        raise ValueError(f"compte {pii['iban']} introuvable pour {pii['email']}")
    except ValueError:
        logger.exception("échec du virement pour %s", pii["nir"], stack_info=True)

    output = stream.getvalue()
    assert leaked(output, pii.values()) == []
    assert "Traceback (most recent call last)" in output
    assert "ValueError: compte [IBAN] introuvable pour [EMAIL:" in output
    assert "Stack (most recent call last)" in output


def test_filter_renders_the_exception_as_redacted_text(pii: dict[str, str]) -> None:
    try:
        raise ValueError(f"aucun compte pour {pii['email']}")
    except ValueError:
        record = logging.LogRecord("app", logging.ERROR, __file__, 1, "échec", None, sys.exc_info())

    assert RedactingFilter(redactor=make_redactor()).filter(record) is True
    assert record.exc_info is None
    assert record.exc_text is not None
    assert "ValueError: aucun compte pour [EMAIL:" in record.exc_text
    assert leaked(logging.Formatter().format(record), pii.values()) == []


def test_key_rules_apply_to_extra_fields(logger: logging.Logger, pii: dict[str, str]) -> None:
    keep = Keep()
    policy = Policy.default().replace(drop_keys=("debug_payload",))
    keep.addFilter(RedactingFilter(redactor=make_redactor(policy)))
    logger.addHandler(keep)

    logger.warning(
        "payload",
        extra={"debug_payload": pii["iban"], "email": pii["email"], "user.id": "customer-7"},
    )

    (record,) = keep.records
    assert not hasattr(record, "debug_payload")
    assert record.email == "[REDACTED]"  # sensitive field name
    assert record.__dict__["user.id"].startswith("[REDACTED:")  # hashed key


def test_structlog_event_dict_message(logger: logging.Logger, pii: dict[str, str]) -> None:
    keep = Keep()
    keep.addFilter(RedactingFilter(redactor=make_redactor()))
    logger.addHandler(keep)

    logger.info({"event": f"connexion de {pii['email']}", "attempt": 2})

    (record,) = keep.records
    assert isinstance(record.msg, dict)
    assert record.msg["attempt"] == 2
    assert leaked(str(record.msg), pii.values()) == []


def test_redaction_is_idempotent_across_filters(
    logger: logging.Logger, pii: dict[str, str]
) -> None:
    keep = Keep()
    keep.addFilter(RedactingFilter(redactor=make_redactor()))
    keep.addFilter(RedactingFilter(redactor=make_redactor()))
    logger.addHandler(keep)

    logger.info("mail %s", pii["email"], extra={"note": pii["phone"]})

    (record,) = keep.records
    once = make_redactor().redact_text(f"mail {pii['email']}")
    assert record.getMessage() == once


def test_failure_quarantines_the_record(logger: logging.Logger, pii: dict[str, str]) -> None:
    keep = Keep()
    redacting = RedactingFilter(redactor=exploding_redactor())
    keep.addFilter(redacting)
    logger.addHandler(keep)

    try:
        raise RuntimeError(pii["email"])
    except RuntimeError:
        logger.exception("échec %s", pii["iban"], extra={"note": pii["phone"]})

    (record,) = keep.records
    assert record.getMessage() == QUARANTINED
    assert record.exc_info is None
    assert record.exc_text is None
    assert record.note == QUARANTINED
    assert redacting.redactor.stats.snapshot() == {"QUARANTINED": 1}


def test_install_on_every_handler(pii: dict[str, str]) -> None:
    # Not registered with logging.getLogger: pytest attaches its own handlers to those,
    # and the filter would stay on them for the next tests.
    logger = logging.Logger("caviard.tests.install", logging.DEBUG)
    logger.propagate = False
    first, second = Keep(), Keep()
    logger.addHandler(first)
    logger.addHandler(second)

    redacting = install(logger=logger, redactor=make_redactor())

    assert redacting in first.filters
    assert redacting in second.filters
    logger.error("contact %s", pii["email"])
    assert leaked(second.records[0].getMessage(), pii.values()) == []


def test_install_needs_a_handler() -> None:
    # Created here: pytest attaches its capture handlers to non-propagating loggers.
    empty = logging.getLogger("caviard.tests.without_handlers")
    with pytest.raises(CaviardError, match="no handler"):
        install(logger=empty, redactor=make_redactor())


def test_install_on_the_root_logger(monkeypatch: pytest.MonkeyPatch) -> None:
    root = logging.getLogger()
    keep = Keep()
    monkeypatch.setattr(root, "handlers", [keep])
    redacting = install(redactor=make_redactor())
    assert keep.filters == [redacting]


def test_from_policy(tmp_path: Path) -> None:
    path = tmp_path / "caviard.toml"
    path.write_text('version = 1\npreset = "strict"\n', encoding="utf-8")
    assert RedactingFilter.from_policy(path).redactor.policy.preset == "strict"


def test_structlog_processor(pii: dict[str, str]) -> None:
    process = structlog_processor(redactor=make_redactor())
    event = process(
        None,
        "info",
        {"event": f"connexion de {pii['email']}", "phone": pii["phone"], "attempt": 2},
    )
    assert event["event"].startswith("connexion de [EMAIL:")
    assert event["phone"] == "[REDACTED]"
    assert event["attempt"] == 2


def test_structlog_processor_quarantine(pii: dict[str, str]) -> None:
    process = structlog_processor(redactor=exploding_redactor())
    assert process(None, "info", {"event": pii["email"]}) == {"event": QUARANTINED}


class _LibraryState:
    """An object a library keeps on its records, under a private name."""


def test_private_extra_fields_with_data_are_redacted(
    logger: logging.Logger, keep: Keep, pii: dict[str, str]
) -> None:
    state = _LibraryState()
    logger.info(
        "commande",
        extra={"_customer": pii["email"], "_rows": [{"tel": pii["phone"]}], "_state": state},
    )

    (record,) = keep.records
    # OpenTelemetry's LoggingHandler and JSON formatters export private fields too.
    assert record._customer.startswith("[EMAIL:")
    assert leaked(str(record._rows), pii.values()) == []
    assert record._state is state  # a library's own state is left alone
