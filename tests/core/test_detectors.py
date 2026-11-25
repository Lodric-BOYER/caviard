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
        assert spans(redactor, f"rib {iban.lower()} reçu") == [iban.lower()]


@pytest.mark.parametrize(
    "text",
    [
        "commit fr00300060000112345678901 fusionné",  # wrong checksum
        "jeton zz12abcdabcdabcdabcd expiré",  # no such country
        "hash de893704004405320130001 calculé",  # a valid IBAN followed by one more digit
    ],
)
def test_iban_lookalikes(redactor: Redactor, text: str) -> None:
    assert entities(redactor, text) == []


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
    for phone in (
        "0033 6 12 34 56 78",
        "06.12.34.56.78",
        "+33612345678",
        "+33 (0)6 12 34 56 78",
        "(+33) 6 12 34 56 78",
        "06  12  34  56  78",
    ):
        assert spans(redactor, f"tél {phone}") == [phone]
    assert spans(redactor, "joindre au (06 12 34 56 78)") == ["06 12 34 56 78"]


@pytest.mark.parametrize(
    "text", ["1234567890", "0012345678", "06 12 34 56", "061234567890", "ab0612345678cd"]
)
def test_phone_lookalikes(redactor: Redactor, text: str) -> None:
    assert entities(redactor, f"valeur {text} fin") == []


def test_email(redactor: Redactor) -> None:
    text = "Écrivez à jean.dupont+test@exemple.co.uk."
    assert spans(redactor, text) == ["jean.dupont+test@exemple.co.uk"]
    assert entities(redactor, "foo@bar n'est pas une adresse") == []
    assert entities(redactor, "toujours pas : x@y.z") == []


@pytest.mark.parametrize(
    "address",
    [
        "inès.robert@exemple.fr",
        "josé@exemple.es",
        "contact@café-crème.fr",
        "李@例え.jp",
        "contact@xn--caf-crme-60ag.fr",  # IDN, as sent on the wire
        r"in\u00e8s.robert@exemple.fr",  # JSON with ensure_ascii
        r"jos\xe9@exemple.es",  # Python repr of Latin-1 bytes
        r"contact@caf\u00e9-cr\u00e8me.fr",
    ],
)
def test_email_with_unicode_letters(redactor: Redactor, address: str) -> None:
    text = f"contact : {address}, merci"
    assert spans(redactor, text) == [address]  # whole address, no letter left in clear
    assert redactor.redact_text(text).startswith("contact : [EMAIL:")


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
def test_secrets(text: str, secret: str) -> None:
    # The detectors alone: field names ("Authorization:") would replace the whole value.
    detectors_only = make_redactor(sensitive_fields=frozenset())
    assert spans(detectors_only, text) == [secret]


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
        ("box 2a01:cb00:1234:5678::1 en ligne", ["2a01:cb00:1234:5678::1"]),
        ("appel de Bad::Cafe et de a::b", []),  # hexadecimal words, no digit
        ("méthode Vec::new et std::vector", []),
        ("interface 00:1a:2b:3c:4d:5e", []),  # a MAC address is no IP address
        ("score 1::2 final", []),
    ],
)
def test_ip_addresses(redactor: Redactor, text: str, expected: list[str]) -> None:
    assert spans(redactor, text) == expected


def test_overlaps_keep_the_best_finding(redactor: Redactor, fake: Faker) -> None:
    assert entities(redactor, "écrire à 0612345678@exemple.fr") == [E.EMAIL]
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


def test_custom_detector_gates() -> None:
    detector = Detector(
        "order",
        "ORDER_ID",
        re.compile(r"CMD-[A-Z0-9]{6}"),
        triggers=("cmd-",),
        requires=("commande",),
        min_digits=4,
    )
    policy = Policy.from_dict({"preset": "none", "plugins": False})
    redactor = Redactor(policy, extra_detectors=[detector], pseudonym_key=TEST_KEY)
    assert entities(redactor, "commande CMD-AB1234") == ["ORDER_ID"]
    assert entities(redactor, "CMD-AB1234") == []  # a required word is missing
    assert entities(redactor, "commande CMD-ABCDEF") == []  # fewer than 4 digits
    assert detectors_module.digit_count("a1b22c333 " + chr(0xFF14)) == 6  # ASCII digits only


def test_invalid_entity_name_is_rejected() -> None:
    with pytest.raises(CaviardError):
        Redactor(Policy(), detectors=[Detector("bad", "bad-name", re.compile("x"))])


def _detectors_only() -> Redactor:
    return make_redactor(sensitive_fields=frozenset())


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("DB_PASSWORD=S3cretPassw0rd", "S3cretPassw0rd"),
        (
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ),
        ("SECRET_KEY=django-insecure-abcdefghijkl", "django-insecure-abcdefghijkl"),
        ("client-secret: Zm9vYmFyYmF6", "Zm9vYmFyYmF6"),
        (
            "Authorization: BEARER abcdefghijklmnopqrstuvwxyz012345",
            "abcdefghijklmnopqrstuvwxyz012345",
        ),
        (
            "Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
            "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b",
        ),
        ("redis://:S3cretPassw0rd@cache:6379/0", "S3cretPassw0rd"),
        ("postgres://app:p@ssw0rd!@db:5432/x", "p@ssw0rd!"),
    ],
)
def test_more_secret_forms(text: str, secret: str) -> None:
    assert spans(_detectors_only(), text) == [secret]


@pytest.mark.parametrize(
    "key",
    [
        "gsk_" + "a1B2c3D4e5" * 5 + "abcd",
        "xai-" + "a1B2c3D4e5" * 8,
        "glpat-" + "a1B2c3D4e5abcdefghij",
        "pypi-AgEIcHlwaS5vcmcCJDAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMAACKlszLCJ",
        "npm_" + "a1B2c3D4e5" * 4,
        "pplx-" + "a1B2c3D4e5" * 4,
        "lsv2_pt_" + "a1B2c3D4e5" * 3,
        "pcsk_" + "a1B2c3D4e5" * 3,
        "tvly-dev-" + "a1B2c3D4e5" * 3,
        "r8_" + "a1B2c3D4e5" * 4,
    ],
)
def test_more_key_prefixes(key: str) -> None:
    assert spans(_detectors_only(), f"clé {key} fin") == [key]


def test_pgp_private_key_blocks() -> None:
    block = (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGXyz0123456789\n"
        "-----END PGP PRIVATE KEY BLOCK-----"
    )
    assert spans(_detectors_only(), f"clé :\n{block}\nfin") == [block]


@pytest.mark.parametrize(
    "text",
    [
        "password_reset_enabled=true",
        "def login(password: str) -> None",
        "password: Optional[str] = None",
        "token 1234567890123456789 tokens used",
        "max_tokens=4096",
        "secret_santa=None",
    ],
)
def test_credential_lookalikes(text: str) -> None:
    assert entities(_detectors_only(), text) == []


def test_iban_with_hyphens(redactor: Redactor, fake: Faker) -> None:
    iban = fake.iban()
    hyphenated = "-".join(iban[i : i + 4] for i in range(0, len(iban), 4))
    assert spans(redactor, f"virement {hyphenated} reçu") == [hyphenated]
