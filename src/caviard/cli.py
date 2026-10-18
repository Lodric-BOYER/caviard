"""Command-line interface.

Every command prints entity types, positions and redacted text. Analysed
values are never printed.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import warnings
from collections.abc import Callable, Sequence
from pathlib import Path

from caviard import __version__
from caviard.core.errors import CaviardError
from caviard.core.policy import Policy
from caviard.core.pseudonym import generate_key
from caviard.core.redactor import Redactor

Handler = Callable[[argparse.Namespace], int]


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

    keygen = commands.add_parser(
        "keygen",
        help="generate a pseudonym key",
        description="Generate a random pseudonym key (32 bytes, base64url). "
        "Store it in CAVIARD_HMAC_KEY or in a key file, never in your repository.",
    )
    keygen.set_defaults(handler=_keygen)
    return parser


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


def _keygen(args: argparse.Namespace) -> int:
    print(generate_key())
    return 0


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
