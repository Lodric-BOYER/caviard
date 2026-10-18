"""Synthetic French agent traces with known personal data. No real data.

``Generator.positive()`` returns a text and the values it contains;
``Generator.negative()`` returns a text that must stay untouched.
"""

from __future__ import annotations

import base64
import json
import random
import string
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from faker import Faker

from caviard.core import entities as E
from helpers import luhn_complete


@dataclass
class Sample:
    text: str
    values: list[tuple[str, str]] = field(default_factory=list)  # (entity, raw value)


def _group(value: str, sizes: tuple[int, ...]) -> str:
    parts: list[str] = []
    index = 0
    for size in sizes:
        if index >= len(value):
            break
        parts.append(value[index : index + size])
        index += size
    if index < len(value):
        parts.append(value[index:])
    return " ".join(parts)


class Generator:
    """Deterministic generator of positive samples and negatives."""

    def __init__(self, seed: int = 2026) -> None:
        self.rng = random.Random(seed)
        self.fake = Faker("fr_FR")
        self.fake.seed_instance(seed)

    # Values, in the formats seen in real traces

    def nir(self) -> str:
        value = self.fake.ssn()
        return value if self.rng.random() < 0.5 else _group(value, (1, 2, 2, 2, 3, 3))

    def iban(self) -> str:
        value = self.fake.iban()
        return value if self.rng.random() < 0.5 else _group(value, (4,) * 8)

    def card(self) -> str:
        value = self.fake.credit_card_number()
        return value if self.rng.random() < 0.5 else _group(value, (4, 4, 4, 4))

    def siren(self) -> str:
        value = self.fake.siren()
        return value if self.rng.random() < 0.5 else value.replace(" ", "")

    def siret(self) -> str:
        value = self.fake.siret()
        return value if self.rng.random() < 0.5 else value.replace(" ", "")

    def rpps(self) -> str:
        return luhn_complete("1" + self.digits(9))

    def phone(self) -> str:
        return str(self.fake.phone_number())

    def email(self) -> str:
        return str(self.fake.email())

    def ip(self) -> str:
        return str(self.fake.ipv4_public() if self.rng.random() < 0.7 else self.fake.ipv6())

    def api_key(self) -> str:
        alphabet = string.ascii_letters + string.digits
        return "sk-proj-" + "".join(self.rng.choice(alphabet) for _ in range(48))

    def jwt(self) -> str:
        def encode(obj: dict[str, object]) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

        alphabet = string.ascii_letters + string.digits + "-_"
        signature = "".join(self.rng.choice(alphabet) for _ in range(43))
        header = encode({"alg": "HS256", "typ": "JWT"})
        payload = encode({"sub": self.digits(8), "iat": 1792314682})
        return f"{header}.{payload}.{signature}"

    def digits(self, count: int) -> str:
        return "".join(self.rng.choice(string.digits) for _ in range(count))

    # Samples

    def positive(self) -> Sample:
        builders: list[Callable[[], Sample]] = [
            self._support,
            self._billing,
            self._company,
            self._health,
            self._payment,
            self._debug,
            self._network,
            self._tool_call,
        ]
        return self.rng.choice(builders)()

    def negative(self) -> str:
        r = self.rng
        templates: list[Callable[[], str]] = [
            lambda: (
                f"Commande CMD-{r.randint(2020, 2026)}-{self.digits(6)} expédiée le "
                f"{self.fake.date()} à {self.fake.time()}."
            ),
            lambda: (
                f"Version {r.randint(0, 9)}.{r.randint(0, 99)}.{r.randint(0, 99)} déployée, "
                f"build b{self.digits(8)} ({uuid.UUID(int=r.getrandbits(128))})."
            ),
            lambda: (
                f"Total : {r.randint(1, 9)} {r.randint(100, 999)},{r.randint(10, 99)} € TTC "
                f"pour {r.randint(1, 40)} articles."
            ),
            lambda: f"Ticket n° {luhn_complete(self.digits(8))} traité en {r.randint(5, 900)} ms.",
            lambda: (
                f"Référence interne {luhn_complete(self.digits(10))}, "
                f"lot {luhn_complete(self.digits(13))}."
            ),
            lambda: (
                f"Horodatage {r.randint(1_700_000_000_000, 1_800_000_000_000)}, "
                f"trace {r.getrandbits(128):032x}, span {r.getrandbits(64):016x}."
            ),
            lambda: (
                f"Code postal {r.randint(10000, 95999)}, année {r.randint(1990, 2026)}, "
                f"quantité {r.randint(1, 500)}."
            ),
            lambda: (
                f"Session {r.randint(10**17, 10**19 - 1)} ouverte, "
                f"latence p95 de {r.randint(50, 2000)} ms."
            ),
            lambda: (
                f"Le modèle mistral-small-{r.randint(2401, 2612)} a consommé "
                f"{r.randint(100, 90000)} tokens."
            ),
        ]
        return r.choice(templates)()

    def _support(self) -> Sample:
        nir, phone, email = self.nir(), self.phone(), self.email()
        text = (
            f"Bonjour, je m'appelle {self.fake.first_name()}. Mon numéro de sécurité sociale "
            f"est {nir}, vous pouvez me joindre au {phone} ou par mail à {email}."
        )
        return Sample(text, [(E.FR_NIR, nir), (E.FR_PHONE, phone), (E.EMAIL, email)])

    def _billing(self) -> Sample:
        iban, siret = self.iban(), self.siret()
        text = (
            f"Merci de régler la facture F-{self.digits(5)} par virement sur l'IBAN {iban}. "
            f"Notre numéro SIRET : {siret}."
        )
        return Sample(text, [(E.IBAN, iban), (E.FR_SIRET, siret)])

    def _company(self) -> Sample:
        siren = self.siren()
        text = (
            f"Kbis reçu : la société {self.fake.company()} (SIREN {siren}) est immatriculée "
            f"au RCS de {self.fake.city()}."
        )
        return Sample(text, [(E.FR_SIREN, siren)])

    def _health(self) -> Sample:
        rpps = self.rpps()
        text = f"Ordonnance du Dr {self.fake.last_name()}, médecin généraliste, n° RPPS {rpps}."
        return Sample(text, [(E.FR_RPPS, rpps)])

    def _payment(self) -> Sample:
        card = self.card()
        month, year = self.rng.randint(1, 12), self.rng.randint(27, 31)
        text = f"Le client a payé par carte bancaire {card} (expiration {month:02d}/{year})."
        return Sample(text, [(E.CARD, card)])

    def _debug(self) -> Sample:
        key, token = self.api_key(), self.jwt()
        text = f"DEBUG appel LLM avec api_key={key} et l'en-tête Authorization: Bearer {token}"
        return Sample(text, [(E.SECRET, key), (E.JWT, token)])

    def _network(self) -> Sample:
        ip = self.ip()
        text = f"Nouvelle connexion de l'utilisateur depuis {ip} à {self.fake.time()}."
        return Sample(text, [(E.IP_ADDRESS, ip)])

    def _tool_call(self) -> Sample:
        name, siret, iban, email = self.fake.name(), self.siret(), self.iban(), self.email()
        arguments = {
            "customer_name": name,
            "siret": siret,
            "iban": iban,
            "contact": email,
            "amount": self.rng.randint(10, 5000),
        }
        messages = [
            {"role": "user", "content": "Crée la facture du mois dernier pour ce client."},
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": f"call_{self.digits(6)}",
                        "type": "function",
                        "function": {
                            "name": "creer_facture",
                            "arguments": json.dumps(arguments, ensure_ascii=False),
                        },
                    }
                ],
            },
        ]
        values = [(E.REDACTED, name), (E.FR_SIRET, siret), (E.IBAN, iban), (E.EMAIL, email)]
        return Sample(json.dumps(messages, ensure_ascii=False), values)
