"""Plain-text rendering of an audit summary, for the terminal."""

from __future__ import annotations

from typing import Any

from caviard.audit.auditor import KIND_LABELS

__all__ = ["render_text"]

_TOP = 15


def render_text(summary: dict[str, Any]) -> str:
    records = summary["records"]
    total, affected = records["total"], records["affected"]
    files = summary["files"]
    kinds = ", ".join(
        f"{KIND_LABELS.get(kind, kind)} {data['records']:,}"
        for kind, data in records["by_kind"].items()
    )
    lines = [
        f"caviard audit: {len(files)} file(s), {total:,} record(s)"
        + (f" ({kinds})" if kinds else ""),
        f"Personal data in {affected:,} record(s)"
        + (f" ({affected / total:.1%})." if total else "."),
    ]
    entities = summary["entities"]
    if entities:
        lines += ["", f"  {'type':<14}{'findings':>10}{'records':>10}  policy"]
        lines += [
            f"  {e['entity']:<14}{e['findings']:>10,}{e['records']:>10,}  {e['action']}"
            for e in entities
        ]
    locations = summary["locations"]
    if locations:
        lines += ["", f"  {'where':<52}{'values':>13}  {'rule':<6} suggestion"]
        for row in locations[:_TOP]:
            where = (
                row["key"]
                + f" [{row['source']}"
                + (f" {row['detail']}" if row["detail"] else "")
                + "]"
            )
            values = f"{row['affected']:,}/{row['values']:,}"
            lines.append(
                f"  {_cut(where, 50):<52}{values:>13}  {row['rule'] or '-':<6} "
                f"{row['suggestion'] or '-'}"
            )
        more = len(locations) - _TOP + summary["more_locations"]
        if more > 0:
            lines.append(f"  ... {more:,} more location(s) in the HTML or JSON report")
    if summary["warnings"]:
        lines += ["", "Warnings:"]
        lines += [f"  - {warning['message']}" for warning in summary["warnings"]]
    return "\n".join(lines)


def _cut(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 3] + "..."
