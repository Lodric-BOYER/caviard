from __future__ import annotations

import re
from types import SimpleNamespace

import pytest
from faker import Faker

from caviard import CaviardError, Detector, Policy, Redactor
from caviard.core import detectors as detectors_module
from caviard.core import entities as E
from helpers import TEST_KEY, luhn_complete, make_redactor, nir_with_key, spaced_nir


def entities(redactor: Redactor, text: str, hint: str = "") -> list[str]:
    return [finding.entity for finding in redactor.findings(text, hint)]


def spans(redactor: Redactor, text: str) -> list[str]:
    return [text[finding.start : finding.end] for finding in redactor.findings(text)]


def test_nir_needs_no_context(redactor: Redactor, fake: Faker) -> None:
    for _ in range(50):
        nir = fake.ssn()
        assert spans(redactor, f"valeur {nir} reçue") == [nir]
        assert spans(redactor, f"valeur {spaced_nir(nir)} reçue") == [spaced_nir(nir)]


def test_nir_with_wrong_key_is_ignored(redactor: Redactor) -> None:
    nir = nir_with_key("1850375112345")
    wrong = nir[:-2] + f"{(int(nir[-2:]) + 1) % 100:02d}"
    assert entities(redactor, f"sécu {nir}") == [E.FR_NIR]
    assert entities(redactor, f"sécu {wrong}") == []


def test_iban_formats(redactor: Redactor, fake: Faker) -> None:
    for _ in range(50):
        iban = fake.iban()
        grouped = " ".join(iban[i : i + 4] for i in range(0, len(iban), 4))
        assert spans(redactor, f"IBAN : {iban}.") == [iban]
        assert spans(redactor, f"payer sur {grouped} merci") == [grouped]


def test_weak_identifiers_need_context(redactor: Redactor, fake: Faker) -> None:
    rpps = luhn_complete("1000812243")
    for _ in range(30):
        siren, siret, card = fake.siren(), fake.siret(), fake.credit_card_number()
        cases = [
            (
                E.FR_SIREN,
                f"La société est inscrite au RCS, SIREN {siren}.",
                f"Ticket {siren} traité.",
            ),
            (E.FR_SIRET, f"SIRET de l'établissement : {siret}", f"Lot {siret} expédié"),
            (E.FR_RPPS, f"Dr Martin, médecin, RPPS {rpps}", f"Commande {rpps} livrée"),
            (E.CARD, f"Paiement par carte {card}", f"Référence {card} archivée"),
        ]
        for entity, positive, negative in cases:
            assert entities(redactor, positive) == [entity], positive
            assert entities(redactor, negative) == [], negative


def test_hint_gives_context(redactor: Redactor, fake: Faker) -> None:
    siret = fake.siret().replace(" ", "")
    assert entities(redactor, siret, hint="customer.siret") == [E.FR_SIRET]
    assert entities(redactor, siret) == []


def test_phone_formats(redactor: Redactor, fake: Faker) -> None:
    for _ in range(100):
        phone = fake.phone_number()
        assert spans(redactor, f"Appelez le {phone} demain") == [phone]
    for phone in ("0033 6 12 34 56 78", "06.12.34.56.78", "+33612345678", "+33 (0)6 12 34 56 78"):
        assert spans(redactor, f"tél {phone}") == [phone]


@pytest.mark.parametrize(
    "text", ["1234567890", "0012345678", "06 12 34 56", "061234567890", "ab0612345678cd"]
)
def test_phone_lookalikes(redactor: Redactor, text: str) -> None:
    assert entities(redactor, f"valeur {text} fin") == []


def test_email(redactor: Redactor) -> None:
    text = "Écrivez à jean.dupont+test@exemple.co.uk."
    assert spans(redactor, text) == ["jean.dupont+test@exemple.co.uk"]
    assert entities(redactor, "pas une adresse : foo@bar") == []
    assert entities(redactor, "toujours pas : x@y.z") == []


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("clé sk-proj-" + "A1b2" * 10, "sk-proj-" + "A1b2" * 10),
        ("aws AKIAIOSFODNN7EXAMPLE ok", "AKIAIOSFODNN7EXAMPLE"),
        ("token ghp_" + "a" * 36, "ghp_" + "a" * 36),
        (
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
            "abcdefghijklmnopqrstuvwxyz012345",
        ),
        ("Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==", "dXNlcjpwYXNzd29yZDEyMw=="),
        ("password=hunter2secret", "hunter2secret"),
        ('body={"user": "x", "password": "hunter2secret"}', "hunter2secret"),
        ("postgres://admin:s3cr3tPass@db.internal:5432/app", "s3cr3tPass"),
        ("mot de passe : Azerty123!", "Azerty123!"),
    ],
)
def test_secrets(redactor: Redactor, text: str, secret: str) -> None:
    assert spans(redactor, text) == [secret]


@pytest.mark.parametrize(
    "text",
    [
        "task-123456789012345678901234567",
        "Basic plan includes everything you need",
        "the token count is high",
    ],
)
def test_secret_lookalikes(redactor: Redactor, text: str) -> None:
    assert entities(redactor, text) == []


def test_private_key_blocks(redactor: Redactor) -> None:
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "q" * 64
    complete = f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"
    truncated = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n"
    for text in (complete, truncated):
        output = redactor.redact_text(f"cle: {text} fin")
        assert body not in output
        assert "[SECRET]" in output


def test_jwt(redactor: Redactor) -> None:
    token = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    assert spans(redactor, f"jeton {token}") == [token]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("client 82.64.12.34 connecté", ["82.64.12.34"]),
        ("depuis 2001:db8::42 hier", ["2001:db8::42"]),
        ("local 127.0.0.1 et ::1 et 0.0.0.0", []),
        ("logiciel v1.2.3.4 installé", []),
        ("à 10:30:45 précises", []),
        ("adresse 999.1.1.1 invalide", []),
        ("mappée ::ffff:82.64.12.34 ok", ["82.64.12.34"]),
    ],
)
def test_ip_addresses(redactor: Redactor, text: str, expected: list[str]) -> None:
    assert spans(redactor, text) == expected


def test_overlaps_keep_the_best_finding(redactor: Redactor, fake: Faker) -> None:
    assert entities(redactor, "écrire à 0612345678@sfr.fr") == [E.EMAIL]
    siret = fake.siret()
    assert entities(redactor, f"SIRET et SIREN de la société : {siret}") == [E.FR_SIRET]


def test_offsets_survive_unicode(redactor: Redactor) -> None:
    text = chr(0x130) * 3 + chr(0x1F600) + " jean@exemple.fr"
    assert spans(redactor, text) == ["jean@exemple.fr"]


def test_min_score_and_keep() -> None:
    phone = "06 12 34 56 78"
    strict = make_redactor(Policy.from_dict({"entities": {"FR_PHONE": {"min_score": 0.88}}}))
    assert entities(strict, f"numéro {phone}") == []
    assert entities(strict, f"tél {phone}") == [E.FR_PHONE]
    disabled = make_redactor(Policy.from_dict({"entities": {"FR_PHONE": "keep"}}))
    assert entities(disabled, f"tél {phone}") == []


def test_plugin_detectors(monkeypatch: pytest.MonkeyPatch) -> None:
    custom = Detector("ticket", "TICKET_ID", re.compile(r"TCK-[0-9]{6}"))
    points = [
        SimpleNamespace(name="single", load=lambda: custom),
        SimpleNamespace(name="factory", load=lambda: lambda: [custom]),
    ]
    monkeypatch.setattr(detectors_module.metadata, "entry_points", lambda group: points)
    assert detectors_module.load_plugin_detectors() == [custom, custom]
    redactor = Redactor(Policy.default(), pseudonym_key=TEST_KEY)
    assert redactor.redact_text("ticket TCK-123456") == "ticket [TICKET_ID]"

    broken = [SimpleNamespace(name="broken", load=lambda: [object()])]
    monkeypatch.setattr(detectors_module.metadata, "entry_points", lambda group: broken)
    with pytest.raises(CaviardError, match="broken"):
        detectors_module.load_plugin_detectors()


def test_invalid_entity_name_is_rejected() -> None:
    with pytest.raises(CaviardError):
        Redactor(Policy(), detectors=[Detector("bad", "bad-name", re.compile("x"))])
