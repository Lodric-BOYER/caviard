"""Audit: counts, locations, suggestions, proposed policy; never an analysed value."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

import pytest

import otlp
from caviard import Policy
from caviard.audit import Auditor, Field, Record, auditor, propose_policy, render_html, render_text
from helpers import exploding_redactor, leaked


def _export(tmp_path: Path, pii: dict[str, str], spans: int = 4) -> Path:
    documents = [
        otlp.traces(
            [
                otlp.span(
                    f"lookup {pii['email']}",
                    {
                        "llm.model_name": "gpt-4o-mini",
                        "gen_ai.usage.input_tokens": 120,
                        f"llm.input_messages.{index}.message.content": (
                            f"Mon NIR est {pii['nir']} et mon tel {pii['phone']}"
                        ),
                        "app.customer.contact": pii["email"],
                        "app.customer.account": pii["iban"],
                        "app.customer_name": "Camille Martin",
                        "tool.arguments": json.dumps({"iban": pii["iban"], "amount": 120}),
                    },
                    events=[("exception", {"exception.message": f"refus pour {pii['email']}"})],
                    status=f"échec {pii['api_key']}",
                )
                for index in range(spans)
            ],
            resource={"service.name": "support-agent", "deployment.owner": pii["email"]},
            scope="openinference.instrumentation.openai",
        ),
        otlp.logs([(f"Connexion de {pii['email']}", {"http.route": "/login"})]),
    ]
    return otlp.write_jsonl(tmp_path / "export.jsonl", documents)


def _summary(path: Path, policy: Policy | None = None, **options: Any) -> dict[str, Any]:
    audit = Auditor(policy, **options)
    audit.add_file(path)
    return audit.summary()


def _row(summary: dict[str, Any], key: str) -> dict[str, Any]:
    return next(row for row in summary["locations"] if row["key"] == key)


def test_reports_never_hold_analysed_values(tmp_path: Path, pii: dict[str, str]) -> None:
    summary = _summary(_export(tmp_path, pii))

    outputs = [json.dumps(summary, ensure_ascii=False), render_html(summary), render_text(summary)]
    for output in outputs:
        assert leaked(output, pii.values()) == []
        assert "Camille" not in output
    assert summary["records"] == {
        "total": 5,
        "affected": 5,
        "by_kind": {"log": {"records": 1, "affected": 1}, "span": {"records": 4, "affected": 4}},
    }
    entities = {row["entity"]: row["findings"] for row in summary["entities"]}
    assert entities["FR_NIR"] == 4
    assert entities["IBAN"] == 4
    assert entities["SECRET"] == 4
    assert entities["REDACTED"] == 8  # customer name and IBAN under sensitive field names
    assert summary["services"] == [
        {"name": "support-agent", "records": 4, "affected": 4, "findings": 36}
    ]
    assert summary["warnings"] == []


def test_examples_are_redacted(tmp_path: Path, pii: dict[str, str]) -> None:
    summary = _summary(_export(tmp_path, pii), examples=3)

    assert leaked(json.dumps(summary, ensure_ascii=False), pii.values()) == []
    assert any("[FR_NIR]" in snippet for snippet in summary["examples"]["FR_NIR"])
    assert "Examples, redacted" in render_html(summary)
    assert all(len(snippets) <= 3 for snippets in summary["examples"].values())


def test_locations_rules_and_suggestions(tmp_path: Path, pii: dict[str, str]) -> None:
    allowed = (*Policy.default().allow_keys, "app.customer.account")
    summary = _summary(_export(tmp_path, pii), Policy.default().replace(allow_keys=allowed))

    prompt = _row(summary, "llm.input_messages.*.message.content")  # indexes grouped
    assert prompt["affected"] == 4
    assert prompt["suggestion"] is None  # free text: detectors cover it
    email = _row(summary, "app.customer.contact")
    assert (email["whole"], email["suggestion"]) == (4, "hash")
    iban = _row(summary, "app.customer.account")
    assert (iban["rule"], iban["suggestion"]) == ("allow", "mask")
    name = _row(summary, "app.customer_name")
    assert (name["findings"], name["rule"], name["suggestion"]) == ({"REDACTED": 4}, "field", None)
    assert _row(summary, "exception.message")["detail"] == "exception"
    assert _row(summary, "status.message")["suggestion"] is None
    assert _row(summary, "deployment.owner")["source"] == "resource"
    assert [warning["code"] for warning in summary["warnings"]] == ["allowed_key_exposes"]

    proposed = tomllib.loads(summary["proposed_policy"])
    assert proposed["keys"]["mask"] == ["app.customer.account"]
    assert proposed["keys"]["hash"] == ["app.customer.contact", "deployment.owner"]
    Policy.from_dict(proposed)  # loads as a valid policy


def test_keys_already_covered_get_no_suggestion(tmp_path: Path, pii: dict[str, str]) -> None:
    policy = Policy.from_dict(
        {"keys": {"mask": ["app.customer.account"], "hash": ["app.*.contact"]}}
    )
    summary = _summary(_export(tmp_path, pii), policy)

    assert _row(summary, "app.customer.contact")["rule"] == "hash"
    assert _row(summary, "app.customer.contact")["suggestion"] is None
    proposed = tomllib.loads(summary["proposed_policy"])
    assert proposed["keys"] == {"hash": ["deployment.owner"]}


def test_clean_export_proposes_no_rule(tmp_path: Path) -> None:
    path = otlp.write_jsonl(
        tmp_path / "clean.jsonl", [otlp.traces([otlp.span("plan", {"step": "ok", "n": 3})])]
    )
    summary = _summary(path)

    assert summary["entities"] == []
    assert summary["locations"] == []
    assert "No key rule needed" in summary["proposed_policy"]
    assert Policy.from_dict(tomllib.loads(summary["proposed_policy"])).preset == "standard"
    assert "None." in render_html(summary)


def test_key_names_with_personal_data_and_glob_characters(pii: dict[str, str]) -> None:
    audit = Auditor()
    audit.add(
        Record(
            "span",
            fields=[
                Field("span", f"visits.{pii['email']}", pii["phone"]),
                Field("span", "odd[key]*.0.contact", pii["email"]),
            ],
        )
    )
    summary = audit.summary()

    assert leaked(json.dumps(summary), pii.values()) == []
    assert [w["code"] for w in summary["warnings"]] == ["personal_keys"]
    assert _row(summary, "odd[key]*.*.contact")["suggestion"] == "hash"
    proposed = tomllib.loads(summary["proposed_policy"])
    assert proposed["keys"]["hash"] == ["odd[[]key][*].*.contact"]  # escaped for globs
    assert Policy.from_dict(proposed).key_decision("odd[key]*.3.contact") == "hash"


def test_skipped_values_and_warnings(pii: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    policy = Policy.default().replace(max_chars=1_000)
    audit = Auditor(policy.replace(entities={**policy.entities, "EMAIL": _keep()}))
    audit.add(
        Record(
            "text",
            fields=[
                Field("text", "line", "x" * 2_000, attribute=False),
                Field("span", "blob", b"\x00\x01"),
                Field("span", "contact", f"écrire à {pii['email']}"),
                Field("span", "empty", ""),
                Field("span", "flag", True),
            ],
        )
    )
    monkeypatch.setattr(audit, "_engine", exploding_redactor())
    audit.add(Record("span", fields=[Field("span", "new.key", "boom")]))
    summary = audit.summary()

    assert summary["skipped"] == {"too_large": 1, "binary": 1, "errors": 1, "unreadable": 0}
    codes = [warning["code"] for warning in summary["warnings"]]
    # A key name that cannot be checked is treated as holding personal data.
    assert codes == ["entity_kept", "personal_keys", "too_large", "binary", "errors"]
    assert next(e for e in summary["entities"] if e["entity"] == "EMAIL")["action"] == "keep"
    assert "keep (exported in clear)" in render_html(summary)


def test_caps_on_locations_and_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auditor, "_MAX_LOCATIONS", 2)
    monkeypatch.setattr(auditor, "_TEXT_CACHE", 1)
    monkeypatch.setattr(auditor, "_MAX_GROUPS", 1)
    monkeypatch.setattr(auditor, "_MAX_ROWS", 2)
    audit = Auditor()
    for index in range(4):
        audit.add(
            Record(
                "record",
                service=f"service-{index}",
                fields=[Field("record", f"key{index}", f"mail{index}@exemple.fr")],
            )
        )
    summary = audit.summary()

    keys = [row["key"] for row in summary["locations"]]
    assert "(other keys)" in keys
    assert summary["more_locations"] == 1
    assert [group["name"] for group in summary["services"]] == ["(other)", "service-0"]
    assert summary["warnings"][-1]["code"] == "many_locations"


def test_unreadable_lines_are_reported(tmp_path: Path) -> None:
    path = tmp_path / "logs.jsonl"
    path.write_text('{"event": "ok"}\ncassé {\n', encoding="utf-8")
    summary = _summary(path)
    assert summary["files"] == [
        {"name": "logs.jsonl", "format": "jsonl", "records": 2, "unreadable": 1}
    ]
    assert summary["warnings"][0]["code"] == "unreadable"


def _keep() -> Any:
    from caviard import Action, EntityRule

    return EntityRule(Action.KEEP)


def test_examples_stop_at_the_limit() -> None:
    audit = Auditor(examples=1)
    for index in range(3):
        audit.add(Record("text", fields=[Field("text", "line", f"mail n{index}@exemple.fr ok")]))
    assert audit.summary()["examples"] == {"EMAIL": ["mail [EMAIL] ok"]}


def test_proposed_policy_with_mask_rules_only() -> None:
    text = propose_policy(
        "strict", mask=["app.b", "app.a", "app.a"], hash_=[], records=3, generated="2026-10-18"
    )
    assert "hash =" not in text
    parsed = tomllib.loads(text)
    assert parsed == {"version": 1, "preset": "strict", "keys": {"mask": ["app.a", "app.b"]}}
