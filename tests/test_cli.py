from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from caviard.cli import main
from caviard.core.pseudonym import decode_key
from helpers import nir_with_key

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
