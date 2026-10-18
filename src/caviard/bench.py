"""``caviard bench``: speed and identifier recall on synthetic French agent traces.

The data is generated on the spot (fictional names, example domains,
identifiers with valid check digits), so the measure can be repeated on any
machine and nothing leaves it. Results only hold counts and timings.
"""

from __future__ import annotations

import itertools
import json
import platform
import random
import statistics
import string
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from caviard.core.checksums import luhn_ok
from caviard.core.policy import Policy
from caviard.core.pseudonym import SecretKey
from caviard.core.redactor import Redactor

__all__ = ["Synthetic", "render_bench", "run_bench"]

_FIRST = ("Camille", "Louis", "Chloé", "Hugo", "Inès", "Lucas", "Manon", "Nathan", "Léa", "Jules")
_LAST = ("Martin", "Bernard", "Dubois", "Thomas", "Robert", "Petit", "Durand", "Leroy", "Moreau")
_DOMAINS = ("exemple.fr", "example.com", "mail.test")
_WARMUP = 20


class Synthetic:
    """Deterministic generator of fictional identifiers with valid check digits."""

    def __init__(self, seed: int = 2026) -> None:
        # A seeded generator on purpose: reproducible test data, nothing secret.
        self.rng = random.Random(seed)  # noqa: S311  # nosec B311

    def digits(self, count: int) -> str:
        return "".join(self.rng.choice(string.digits) for _ in range(count))

    def name(self) -> str:
        return f"{self.rng.choice(_FIRST)} {self.rng.choice(_LAST)}"

    def email(self) -> str:
        first = _ascii(self.rng.choice(_FIRST)).lower()
        last = self.rng.choice(_LAST).lower()
        return f"{first}.{last}{self.rng.randint(1, 99)}@{self.rng.choice(_DOMAINS)}"

    def phone(self) -> str:
        number = "0" + self.rng.choice("67") + self.digits(8)
        pairs = " ".join(number[i : i + 2] for i in range(0, 10, 2))
        return self.rng.choice((pairs, number, "+33 " + pairs[1:]))

    def nir(self) -> str:
        department = self.rng.choice([d for d in range(1, 96) if d != 20])
        body = (
            self.rng.choice("12")
            + f"{self.rng.randint(40, 99):02d}{self.rng.randint(1, 12):02d}"
            + f"{department:02d}{self.rng.randint(1, 990):03d}{self.rng.randint(1, 999):03d}"
        )
        value = f"{body}{97 - int(body) % 97:02d}"
        if self.rng.random() < 0.5:
            return value
        bounds = (0, 1, 3, 5, 7, 10, 13, 15)
        return " ".join(value[a:b] for a, b in itertools.pairwise(bounds))

    def iban(self) -> str:
        bban = self.digits(23)
        value = f"FR{98 - int(bban + '152700') % 97:02d}{bban}"  # F=15, R=27 (ISO 13616)
        if self.rng.random() < 0.5:
            return value
        return " ".join(value[i : i + 4] for i in range(0, len(value), 4))

    def card(self) -> str:
        value = _luhn_complete("4" + self.digits(14))
        if self.rng.random() < 0.5:
            return value
        return " ".join(value[i : i + 4] for i in range(0, 16, 4))

    def siret(self) -> str:
        return _luhn_complete(self.digits(13))

    def api_key(self) -> str:
        alphabet = string.ascii_letters + string.digits
        return "sk-proj-" + "".join(self.rng.choice(alphabet) for _ in range(48))

    def ip(self) -> str:
        first = self.rng.choice([n for n in range(11, 224) if n != 127])
        rest = (self.rng.randint(0, 255), self.rng.randint(0, 255), self.rng.randint(1, 254))
        return ".".join(str(part) for part in (first, *rest))

    # Texts: (text, identifiers it holds)

    def message(self) -> tuple[str, list[str]]:
        email, phone, nir = self.email(), self.phone(), self.nir()
        iban, card, siret = self.iban(), self.card(), self.siret()
        key, ip = self.api_key(), self.ip()
        templates: list[tuple[str, list[str]]] = [
            (
                f"Bonjour, je suis {self.name()}. Mon numéro de sécurité sociale est {nir} "
                f"et vous pouvez m'écrire à {email}.",
                [nir, email],
            ),
            (f"Merci de rembourser sur l'IBAN {iban}, mon téléphone : {phone}.", [iban, phone]),
            (f"Paiement refusé pour la carte bancaire {card}, client {email}.", [card, email]),
            (f"Fournisseur ajouté : SIRET {siret}, contact au {phone}.", [siret, phone]),
            (f"Erreur 401 avec la clé {key} depuis {ip}.", [key, ip]),
        ]
        return self.rng.choice(templates)

    def clean(self) -> str:
        return self.rng.choice(
            (
                f"La commande n°{self.digits(6)} a été expédiée par le transporteur standard.",
                f"Version 3.{self.rng.randint(0, 20)}.{self.rng.randint(0, 9)} déployée, "
                f"{self.rng.randint(10, 900)} tests passés.",
                "Résumé de la réunion : planning validé, prochaine étape la semaine prochaine.",
                f"Le modèle a répondu en {self.rng.randint(80, 2500)} ms avec "
                f"{self.rng.randint(20, 900)} tokens.",
                f"Le ticket SUP-{self.digits(4)} est fermé, le client est satisfait.",
            )
        )


@dataclass
class _Scenario:
    name: str
    inputs: list[Any]
    values: list[list[str]]
    run: Callable[[Any], Any]
    clean: bool = False


def run_bench(
    policy: Policy | None = None, *, count: int = 1000, seed: int = 2026
) -> dict[str, Any]:
    """Time the redaction of synthetic inputs and measure how many identifiers remain."""
    if count < 1:
        raise ValueError("count must be at least 1")
    policy = policy if policy is not None else Policy.default()
    redactor = Redactor(policy, pseudonym_key=SecretKey.generate())
    data = Synthetic(seed)
    results = [_measure(scenario) for scenario in _scenarios(data, redactor, count)]
    return {
        "python": platform.python_version(),
        "platform": platform.platform(terse=True),
        "policy": policy.preset,
        "count": count,
        "seed": seed,
        "scenarios": results,
    }


def _scenarios(data: Synthetic, redactor: Redactor, count: int) -> list[_Scenario]:
    messages = [data.message() for _ in range(count)]
    long_inputs = [_long_text(data) for _ in range(max(1, count // 10))]
    spans = [_span(data) for _ in range(count)]
    return [
        _Scenario(
            "message with identifiers",
            [text for text, _ in messages],
            [values for _, values in messages],
            redactor.redact_text,
        ),
        _Scenario(
            "clean message",
            [data.clean() for _ in range(count)],
            [[] for _ in range(count)],
            redactor.redact_text,
            clean=True,
        ),
        _Scenario(
            "tool output (8 kB)",
            [text for text, _ in long_inputs],
            [values for _, values in long_inputs],
            redactor.redact_text,
        ),
        _Scenario(
            "span attributes",
            [attributes for attributes, _ in spans],
            [values for _, values in spans],
            redactor.redact_attributes,
        ),
    ]


def _measure(scenario: _Scenario) -> dict[str, Any]:
    for item in scenario.inputs[:_WARMUP]:
        scenario.run(item)
    timings: list[int] = []
    missed = changed = 0
    for item, values in zip(scenario.inputs, scenario.values, strict=True):
        start = time.perf_counter_ns()
        output = scenario.run(item)
        timings.append(time.perf_counter_ns() - start)
        text = _text(output)
        missed += sum(1 for value in values if value in text)
        changed += 1 if scenario.clean and output != item else 0
    size = sum(len(_text(item).encode()) for item in scenario.inputs)
    identifiers = sum(len(values) for values in scenario.values)
    total_ns = max(1, sum(timings))
    return {
        "name": scenario.name,
        "inputs": len(scenario.inputs),
        "mean_us": round(total_ns / len(timings) / 1000, 1),
        "p50_us": round(statistics.median(timings) / 1000, 1),
        "p99_us": round(_percentile(timings, 0.99) / 1000, 1),
        "mb_per_s": round(size / total_ns * 1000, 2),
        "identifiers": identifiers,
        "missed": missed,
        "recall": round(1 - missed / identifiers, 4) if identifiers else None,
        "changed_clean_inputs": changed if scenario.clean else None,
    }


def render_bench(result: dict[str, Any]) -> str:
    """Plain-text table of a benchmark result."""
    lines = [
        f"caviard bench: Python {result['python']}, policy {result['policy']!r}, "
        f"{result['count']} inputs per scenario, seed {result['seed']}",
        "",
        f"  {'scenario':<26}{'inputs':>7}{'mean us':>10}{'p50 us':>9}{'p99 us':>9}"
        f"{'MB/s':>8}  {'recall':<10}",
    ]
    for row in result["scenarios"]:
        if row["recall"] is not None:
            quality = f"{row['recall']:.1%}"
        else:
            quality = f"{row['changed_clean_inputs']} changed"
        lines.append(
            f"  {row['name']:<26}{row['inputs']:>7}{row['mean_us']:>10.1f}{row['p50_us']:>9.1f}"
            f"{row['p99_us']:>9.1f}{row['mb_per_s']:>8.2f}  {quality:<10}"
        )
    lines += [
        "",
        "Recall: share of synthetic identifiers removed. Names in free text are not detected;",
        "clean messages must stay unchanged. Timings depend on this machine.",
    ]
    return "\n".join(lines)


def _long_text(data: Synthetic) -> tuple[str, list[str]]:
    lines: list[str] = []
    values: list[str] = []
    size = 0
    while size < 8_000:
        if data.rng.random() < 0.1:
            line, found = data.message()
            values += found
        else:
            line = data.clean()
        lines.append(line)
        size += len(line) + 1
    return "\n".join(lines), values


def _span(data: Synthetic) -> tuple[dict[str, Any], list[str]]:
    prompt, values = data.message()
    name, iban, phone = data.name(), data.iban(), data.phone()
    attributes = {
        "gen_ai.request.model": "gpt-4o-mini",
        "gen_ai.usage.input_tokens": data.rng.randint(50, 4000),
        "gen_ai.usage.output_tokens": data.rng.randint(10, 800),
        "gen_ai.prompt": prompt,
        "gen_ai.completion": data.clean(),
        "gen_ai.tool.name": "lookup_customer",
        "gen_ai.tool.call.arguments": json.dumps(
            {"customer_name": name, "iban": iban, "note": f"rappeler au {phone}"},
            ensure_ascii=False,
        ),
        "enduser.id": f"customer-{data.digits(6)}",
        "http.request.method": "POST",
        "server.address": "api.exemple.fr",
    }
    # The name is replaced through its field name but not tracked: the same fictional
    # name may also appear in the prompt, where names are not detected.
    return attributes, [*values, iban, phone]


def _text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _percentile(values: list[int], share: float) -> float:
    ordered = sorted(values)
    return float(ordered[min(len(ordered) - 1, round(share * (len(ordered) - 1)))])


def _luhn_complete(prefix: str) -> str:
    return next(prefix + digit for digit in string.digits if luhn_ok(prefix + digit))


def _ascii(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
