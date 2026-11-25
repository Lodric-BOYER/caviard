"""Fail CI on known vulnerabilities in the dependencies that a new install gets.

CI resolves the dependencies of every extra to their latest releases, without installing
them, and pip-audit checks these versions. This script turns each advisory, and each
dependency that could not be checked, into an error annotation.

Usage: python scripts/audit_dependencies.py audit.json  (output of pip-audit --format json)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(path: str) -> int:
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    dependencies = report["dependencies"]
    problems: list[str] = []
    for dependency in dependencies:
        name, version = dependency["name"], dependency.get("version", "")
        if "skip_reason" in dependency:
            problems.append(f"{name}: not checked ({dependency['skip_reason']})")
        for vuln in dependency.get("vulns", []):
            fixes = vuln.get("fix_versions") or []
            status = f"fixed in {', '.join(fixes)}" if fixes else "no fixed version yet"
            problems.append(f"{name} {version}: {vuln['id']} ({status})")
    for line in problems:
        print(f"::error::{line}")
    print(f"{len(dependencies)} dependencies checked, {len(problems)} problem(s)")
    return 1 if problems or not dependencies else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
