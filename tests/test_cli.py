from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import otlp
from caviard import Policy
from caviard.cli import main
from caviard.core.pseudonym import decode_key
from helpers import leaked, nir_with_key

NIR = nir_with_key("1850375112345")
TEXT = f"Mon mail est jean.dupont@exemple.fr et ma sécu {NIR}."


def test_scan_never_prints_values(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", TEXT]) == 0
    out = capsys.readouterr().out
    assert "2 finding(s)" in out
    assert "EMAIL" in out
    assert "FR_NIR" in out
    assert "jean.dupont@exemple.fr" not in out
    assert NIR not in out


def test_scan_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--json", TEXT]) == 0
    document = json.loads(capsys.readouterr().out)
    assert [f["entity"] for f in document["findings"]] == ["EMAIL", "FR_NIR"]
    assert NIR not in document["redacted"]


def test_scan_check_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "--check", TEXT]) == 1
    assert main(["scan", "--check", "rien à signaler"]) == 0


def test_scan_stdin_and_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(TEXT))
    assert main(["scan"]) == 0
    assert "FR_NIR" in capsys.readouterr().out
    trace = tmp_path / "trace.txt"
    trace.write_text(TEXT, encoding="utf-8")
    assert main(["scan", "--file", str(trace)]) == 0
    assert "FR_NIR" in capsys.readouterr().out


def test_scan_with_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text('[entities]\nEMAIL = "keep"\n', encoding="utf-8")
    assert main(["scan", "--policy", str(policy), TEXT]) == 0
    out = capsys.readouterr().out
    assert "1 finding(s)" in out
    assert "jean.dupont@exemple.fr" in out  # kept on purpose by the policy


def test_errors_are_reported_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = tmp_path / "policy.toml"
    policy.write_text("unknown = 1\n", encoding="utf-8")
    assert main(["scan", "--policy", str(policy), TEXT]) == 2
    assert "caviard: error: unknown policy key(s): unknown" in capsys.readouterr().err
    assert main(["scan", "--file", str(tmp_path / "absent.txt")]) == 2


def test_keygen(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["keygen"]) == 0
    assert len(decode_key(capsys.readouterr().out.strip())) == 32


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "scan" in capsys.readouterr().out


# audit


def _export(tmp_path: Path, pii: dict[str, str]) -> Path:
    request = otlp.traces(
        [
            otlp.span(
                "chat",
                {"gen_ai.prompt": f"Mon NIR est {pii['nir']}", "app.contact": pii["email"]},
            )
        ],
        resource={"service.name": "support-agent"},
    )
    return otlp.write_jsonl(tmp_path / "export.jsonl", [request])


def test_audit_text_report_and_policy(
    tmp_path: Path, pii: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    export = _export(tmp_path, pii)
    report, proposed = tmp_path / "report.html", tmp_path / "proposed.toml"

    code = main(["audit", str(export), "-o", str(report), "--policy-out", str(proposed)])

    assert code == 0
    out = capsys.readouterr().out
    assert "caviard audit: 1 file(s), 1 record(s) (spans 1)" in out
    assert "FR_NIR" in out
    assert "Written:" in out
    for output in (out, report.read_text(encoding="utf-8"), proposed.read_text(encoding="utf-8")):
        assert leaked(output, pii.values()) == []
    assert Policy.load(proposed).key_decision("app.contact") == "hash"


def test_audit_json_check_and_inputs(
    tmp_path: Path, pii: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    export = _export(tmp_path, pii)
    clean = tmp_path / "clean.log"
    clean.write_text("rien à signaler\n", encoding="utf-8")

    assert main(["audit", "--json", "--check", str(export)]) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["records"]["affected"] == 1
    assert main(["audit", "--check", str(clean)]) == 0
    capsys.readouterr()
    # A directory and a glob pattern, as typed in PowerShell (no shell expansion).
    assert main(["audit", "--json", str(tmp_path)]) == 0
    assert len(json.loads(capsys.readouterr().out)["files"]) == 2
    assert main(["audit", "--json", str(tmp_path / "*.jsonl")]) == 0
    assert len(json.loads(capsys.readouterr().out)["files"]) == 1


def test_audit_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["audit", str(tmp_path / "absent.jsonl")]) == 2
    assert main(["audit", str(tmp_path / "*.nothing")]) == 2
    assert main(["audit", "--examples", "-1", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "cannot read 'absent.jsonl'" in err
    assert "no file matches" in err
    assert "--examples" in err
    report = tmp_path / "missing-dir" / "report.html"
    _export(tmp_path, {"nir": "-", "email": "-"})
    assert main(["audit", str(tmp_path / "export.jsonl"), "-o", str(report)]) == 2
    assert "cannot write 'report.html'" in capsys.readouterr().err


# policy check


def test_policy_check_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CAVIARD_HMAC_KEY", "a" * 64)
    policy = tmp_path / "caviard.toml"
    policy.write_text('version = 1\npreset = "standard"\n', encoding="utf-8")

    assert main(["policy", "check", str(policy)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("caviard.toml: valid")
    assert "CAVIARD_HMAC_KEY: set (needed)" in out
    assert "a" * 64 not in out  # the key itself is never printed
    assert "warning" not in out


def test_policy_check_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("CAVIARD_HMAC_KEY", raising=False)
    policy = tmp_path / "caviard.toml"
    policy.write_text(
        'version = 1\n[keys]\nallow = ["app.*"]\nmask = ["app.*"]\n'
        '[entities]\nTICKET_ID = "mask"\n',
        encoding="utf-8",
    )

    assert main(["policy", "check", str(policy)]) == 0
    out = capsys.readouterr().out
    assert "warning: entities.TICKET_ID: no detector reports this entity" in out
    assert "warning: pseudonyms need a key: set CAVIARD_HMAC_KEY" in out
    assert "warning: 'app.*' is in keys.allow and keys.mask: keys.mask wins" in out
    assert main(["policy", "check", "--strict", str(policy)]) == 1
    capsys.readouterr()
    assert main(["policy", "check", "--json", str(policy)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["pseudonym"] == {
        "key_source": "CAVIARD_HMAC_KEY",
        "key_configured": False,
        "needed": True,
        "length": 12,
    }
    assert len(report["warnings"]) == 3


def test_policy_check_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    broken = tmp_path / "broken.toml"
    broken.write_text("unknown = 1\n", encoding="utf-8")
    assert main(["policy", "check", str(broken)]) == 2
    key_file = tmp_path / "key.toml"
    key_file.write_text(f'[pseudonym]\nkey_file = "{(tmp_path / "absent.key").as_posix()}"\n')
    assert main(["policy", "check", str(key_file)]) == 2
    err = capsys.readouterr().err
    assert "unknown policy key(s): unknown" in err
    assert "cannot read the pseudonym key file" in err
    assert main(["policy"]) == 0
    assert "check" in capsys.readouterr().out


def test_policy_check_without_hash(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy = tmp_path / "strict.toml"
    policy.write_text('preset = "strict"\n[pseudonym]\nkey_env = ""\n', encoding="utf-8")
    assert main(["policy", "check", str(policy)]) == 0
    out = capsys.readouterr().out
    assert "pseudonym key  none: not set (not needed by this policy)" in out
    assert "drop" in out


# bench


def test_bench(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["bench", "--count", "5"]) == 0
    assert "message with identifiers" in capsys.readouterr().out
    assert main(["bench", "--count", "5", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["scenarios"]) == 4
    assert main(["bench", "--count", "0"]) == 2
