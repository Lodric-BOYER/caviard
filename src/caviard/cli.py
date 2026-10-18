"""Command-line interface.

Every command prints entity types, counts, positions or redacted text.
Analysed values are never printed.
"""

from __future__ import annotations

import argparse
import contextlib
import glob
import json
import sys
import warnings
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from caviard import __version__
from caviard.core import entities as E
from caviard.core.detectors import builtin_detectors, load_plugin_detectors
from caviard.core.errors import CaviardError
from caviard.core.policy import Action, Policy
from caviard.core.pseudonym import generate_key, resolve_key
from caviard.core.redactor import Redactor

Handler = Callable[[argparse.Namespace], int]
_PRIORITY = ("drop", "mask", "hash", "allow")  # key rule precedence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="caviard",
        description="Fail-closed redaction of personal data in AI agent traces and logs.",
    )
    parser.add_argument("--version", action="version", version=f"caviard {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = commands.add_parser(
        "scan",
        help="show what would be redacted in a text (values are never printed)",
        description="Show what would be redacted in a text. Values are never printed.",
    )
    scan.add_argument(
        "text", nargs="?", help="text to analyse; omit it or use '-' to read standard input"
    )
    scan.add_argument("-f", "--file", type=Path, help="read the text from a file (UTF-8)")
    scan.add_argument("-p", "--policy", type=Path, help="policy file (.toml, .yaml or .json)")
    scan.add_argument("--json", action="store_true", help="print a JSON document")
    scan.add_argument(
        "--check", action="store_true", help="exit with status 1 when something is found"
    )
    scan.set_defaults(handler=_scan)

    _add_audit(commands)
    _add_policy(commands)

    bench = commands.add_parser(
        "bench",
        help="measure speed and recall on synthetic traces",
        description="Measure redaction speed and identifier recall on synthetic French "
        "agent traces generated on this machine.",
    )
    bench.add_argument("-p", "--policy", type=Path, help="policy file to measure")
    bench.add_argument(
        "-n", "--count", type=int, default=1000, help="inputs per scenario (default: 1000)"
    )
    bench.add_argument("--seed", type=int, default=2026, help="seed of the synthetic data")
    bench.add_argument("--json", action="store_true", help="print a JSON document")
    bench.set_defaults(handler=_bench)

    keygen = commands.add_parser(
        "keygen",
        help="generate a pseudonym key",
        description="Generate a random pseudonym key (32 bytes, base64url). "
        "Store it in CAVIARD_HMAC_KEY or in a key file, never in your repository.",
    )
    keygen.set_defaults(handler=_keygen)
    return parser


def _add_audit(commands: Any) -> None:
    from caviard.audit.readers import FORMATS

    audit = commands.add_parser(
        "audit",
        help="report the personal data held by exported traces or logs",
        description="Analyse exported traces or logs (OTLP JSON from the OpenTelemetry "
        "Collector, JSON Lines or text, optionally .gz) and report which personal data they "
        "hold and where. The report holds counts, types and redacted names only.",
    )
    audit.add_argument(
        "paths", nargs="+", type=Path, metavar="PATH", help="export file, directory or pattern"
    )
    audit.add_argument("-p", "--policy", type=Path, help="policy file to audit against")
    audit.add_argument(
        "-f", "--format", choices=FORMATS, default="auto", help="input format (default: auto)"
    )
    audit.add_argument("-o", "--out", type=Path, help="write an HTML report to this file")
    audit.add_argument("--policy-out", type=Path, help="write the proposed policy (TOML)")
    audit.add_argument(
        "--examples",
        type=int,
        default=0,
        metavar="N",
        help="add up to N redacted examples per type to the report; the text around them "
        "may hold names, so keep such a report internal",
    )
    audit.add_argument("--json", action="store_true", help="print the summary as JSON")
    audit.add_argument(
        "--check", action="store_true", help="exit with status 1 when personal data is found"
    )
    audit.set_defaults(handler=_audit)


def _add_policy(commands: Any) -> None:
    policy = commands.add_parser(
        "policy", help="work with policy files", description="Work with policy files."
    )
    actions = policy.add_subparsers(dest="action", metavar="ACTION")
    check = actions.add_parser(
        "check",
        help="validate a policy file and show its effective settings",
        description="Validate a policy file and show its effective settings (preset merged).",
    )
    check.add_argument("file", type=Path, help="policy file (.toml, .yaml or .json)")
    check.add_argument("--json", action="store_true", help="print a JSON document")
    check.add_argument("--strict", action="store_true", help="exit with status 1 on warnings")
    check.set_defaults(handler=_policy_check)
    policy.set_defaults(handler=_help, help_parser=policy)


def main(argv: Sequence[str] | None = None) -> int:
    _tolerant_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Handler | None = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    try:
        return handler(args)
    except CaviardError as exc:
        print(f"caviard: error: {exc}", file=sys.stderr)
        return 2


def _help(args: argparse.Namespace) -> int:
    args.help_parser.print_help()
    return 0


def _scan(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy) if args.policy else Policy.default()
    text = _read_input(args)
    policy = policy.replace(max_chars=max(policy.max_chars, len(text) + 1))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # a preview does not need a stable pseudonym key
        redactor = Redactor(policy)
    findings = redactor.findings(text)
    redacted = redactor.redact_text(text) if findings else text
    if args.json:
        document = {
            "findings": [
                {
                    "entity": f.entity,
                    "start": f.start,
                    "end": f.end,
                    "score": round(f.score, 2),
                    "detector": f.detector,
                }
                for f in findings
            ],
            "redacted": redacted,
        }
        print(json.dumps(document, ensure_ascii=False, indent=2))
    else:
        print(f"{len(findings)} finding(s)")
        for f in findings:
            print(f"  {f.entity:<12} {f.start:>6}-{f.end:<6} score {f.score:.2f}  ({f.detector})")
        print()
        print(redacted)
    return 1 if args.check and findings else 0


def _audit(args: argparse.Namespace) -> int:
    from caviard.audit import Auditor, render_html, render_text

    if args.examples < 0:
        raise CaviardError("--examples: expected a positive number")
    policy = Policy.load(args.policy) if args.policy else Policy.default()
    auditor = Auditor(
        policy, policy_source=args.policy.name if args.policy else None, examples=args.examples
    )
    for path in _expand(args.paths):
        auditor.add_file(path, args.format)
    summary = auditor.summary()
    if args.out:
        _write(args.out, render_html(summary))
    if args.policy_out:
        _write(args.policy_out, summary["proposed_policy"])
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(render_text(summary))
        written = [str(path) for path in (args.out, args.policy_out) if path]
        if written:
            print("\nWritten: " + ", ".join(written))
    found = any(entity["findings"] for entity in summary["entities"])
    return 1 if args.check and found else 0


def _policy_check(args: argparse.Namespace) -> int:
    policy = Policy.load(args.file)
    report = _policy_report(policy, args.file.name)
    print(json.dumps(report, indent=2) if args.json else _render_policy(report))
    return 1 if args.strict and report["warnings"] else 0


def _policy_report(policy: Policy, name: str) -> dict[str, Any]:
    plugins = list(load_plugin_detectors()) if policy.plugins else []
    entities = sorted({detector.entity for detector in [*builtin_detectors(), *plugins]})
    problems = [
        f"entities.{entity}: no detector reports this entity"
        for entity in sorted(policy.entities)
        if entity not in entities and entity not in E.SPECIAL
    ]
    uses_hash = (
        bool(policy.hash_keys)
        or policy.default_action is Action.HASH
        or any(rule.action is Action.HASH for rule in policy.entities.values())
    )
    key = resolve_key(policy.key_env, policy.key_file)
    if uses_hash and key is None:
        where = f"set {policy.key_env}" if policy.key_env else "set pseudonym.key_file"
        problems.append(
            f"pseudonyms need a key: {where} (see `caviard keygen`), otherwise they change "
            "at every restart"
        )
    lists = {
        "allow": policy.allow_keys,
        "mask": policy.mask_keys,
        "hash": policy.hash_keys,
        "drop": policy.drop_keys,
    }
    owners: dict[str, list[str]] = {}
    for rule, patterns in lists.items():
        for pattern in patterns:
            owners.setdefault(pattern, []).append(rule)
    for pattern, rules in sorted(owners.items()):
        if len(rules) > 1:
            winner = next(rule for rule in _PRIORITY if rule in rules)
            listed = " and ".join(f"keys.{rule}" for rule in rules)
            problems.append(f"'{pattern}' is in {listed}: keys.{winner} wins")
    source = "pseudonym.key_file" if policy.key_file else (policy.key_env or "none")
    return {
        "file": name,
        "valid": True,
        "preset": policy.preset,
        "on_error": policy.on_error.value,
        "max_chars": policy.max_chars,
        "json_max_depth": policy.json_max_depth,
        "sensitive_fields": len(policy.sensitive_fields),
        "keys": {rule: len(patterns) for rule, patterns in lists.items()},
        "entities": {entity: policy.rule(entity).action.value for entity in entities},
        "pseudonym": {
            "key_source": source,
            "key_configured": key is not None,
            "needed": uses_hash,
            "length": policy.pseudonym_length,
        },
        "plugins": sorted({detector.name for detector in plugins}),
        "warnings": problems,
    }


def _render_policy(report: dict[str, Any]) -> str:
    by_action: dict[str, list[str]] = {}
    for entity, action in report["entities"].items():
        by_action.setdefault(action, []).append(entity)
    actions = "; ".join(
        f"{action} {', '.join(names)}" for action, names in sorted(by_action.items())
    )
    pseudonym = report["pseudonym"]
    state = "set" if pseudonym["key_configured"] else "not set"
    usage = "needed" if pseudonym["needed"] else "not needed by this policy"
    keys = ", ".join(f"{rule} {count}" for rule, count in report["keys"].items())
    lines = [
        f"{report['file']}: valid",
        f"  preset         {report['preset']}",
        f"  on_error       {report['on_error']}",
        f"  max_chars      {report['max_chars']:,}",
        f"  json           depth {report['json_max_depth']}, "
        f"{report['sensitive_fields']} sensitive field names",
        f"  keys           {keys}",
        f"  pseudonym key  {pseudonym['key_source']}: {state} ({usage})",
        f"  entities       {actions}",
        f"  plugins        {', '.join(report['plugins']) or 'none'}",
    ]
    lines += [f"warning: {problem}" for problem in report["warnings"]]
    return "\n".join(lines)


def _bench(args: argparse.Namespace) -> int:
    from caviard.bench import render_bench, run_bench

    if args.count < 1:
        raise CaviardError("--count: expected a positive number")
    policy = Policy.load(args.policy) if args.policy else Policy.default()
    result = run_bench(policy, count=args.count, seed=args.seed)
    print(json.dumps(result, indent=2) if args.json else render_bench(result))
    return 0


def _keygen(args: argparse.Namespace) -> int:
    print(generate_key())
    return 0


def _expand(paths: Sequence[Path]) -> list[Path]:
    """Files named by paths, directories (their files) and glob patterns."""
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files += sorted(item for item in path.iterdir() if item.is_file())
        elif path.exists():
            files.append(path)
        elif glob.has_magic(str(path)):
            matches = sorted(Path(item) for item in glob.glob(str(path)))
            if not matches:
                raise CaviardError(f"no file matches {path.name!r}")
            files += [item for item in matches if item.is_file()]
        else:
            raise CaviardError(f"cannot read {path.name!r}")
    return files


def _write(path: Path, text: str) -> None:
    try:
        path.write_text(text, encoding="utf-8")
    except OSError:
        raise CaviardError(f"cannot write {path.name!r}") from None


def _read_input(args: argparse.Namespace) -> str:
    file: Path | None = args.file
    if file is not None:
        try:
            return file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            raise CaviardError(f"cannot read {file.name!r}") from None
    if args.text is not None and args.text != "-":
        return str(args.text)
    return sys.stdin.read()


def _tolerant_output() -> None:
    # Windows consoles and pipes may not be UTF-8: replace unprintable characters.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="replace")
