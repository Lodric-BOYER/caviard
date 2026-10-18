"""Self-contained HTML rendering of an audit summary (no script, no external resource).

Every string that comes from the summary is escaped. The summary itself only
holds counts, entity types and redacted names, so the page can be shared.
"""

from __future__ import annotations

from html import escape
from typing import Any

from caviard.audit.auditor import KIND_LABELS

__all__ = ["render_html"]

_CSS = """
:root { color-scheme: light dark; --bg: #f6f7f9; --card: #ffffff; --ink: #16181d;
  --muted: #5f6672; --line: #e3e6eb; --accent: #0f766e; --accent-soft: #e6f4f2;
  --warn: #b45309; --warn-soft: #fdf3e7; --chip: #eef0f3; }
@media (prefers-color-scheme: dark) { :root { --bg: #111317; --card: #1a1d23;
  --ink: #e8eaee; --muted: #9aa1ad; --line: #2c3038; --accent: #2dd4bf;
  --accent-soft: #123532; --warn: #f59e0b; --warn-soft: #33270f; --chip: #262a32; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1120px; margin: 0 auto; padding: 32px 16px 48px; }
header h1 { margin: 0; font-size: 26px; letter-spacing: -0.01em; }
header .brand { color: var(--accent); font-weight: 700; }
.meta { color: var(--muted); margin: 6px 0 0; font-size: 13px; }
h2 { font-size: 18px; margin: 36px 0 12px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px; margin-top: 24px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 14px 16px; }
.card .value { font-size: 26px; font-weight: 650; }
.card .label { color: var(--muted); font-size: 13px; }
.panel { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase;
  letter-spacing: 0.04em; }
tr:last-child td { border-bottom: 0; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
code, .mono { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace;
  font-size: 13px; }
td code { overflow-wrap: anywhere; }
.chip { display: inline-block; background: var(--chip); border-radius: 6px;
  padding: 1px 7px; margin: 1px 2px 1px 0; font-size: 12px; white-space: nowrap; }
.badge { display: inline-block; border-radius: 6px; padding: 1px 7px; font-size: 12px;
  font-weight: 600; background: var(--accent-soft); color: var(--accent); }
.badge.warn { background: var(--warn-soft); color: var(--warn); }
.source { color: var(--muted); font-size: 12px; }
.bar { height: 8px; border-radius: 4px; background: var(--accent); min-width: 2px; }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 12px; }
.warnings li { background: var(--warn-soft); border-left: 3px solid var(--warn);
  padding: 8px 12px; margin: 6px 0; border-radius: 0 8px 8px 0; list-style: none; }
.warnings { padding: 0; margin: 0; }
.note { background: var(--accent-soft); border-radius: 8px; padding: 10px 14px; }
.caution { background: var(--warn-soft); border-radius: 8px; padding: 10px 14px; }
pre { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 14px 16px; overflow-x: auto; margin: 0; }
footer { color: var(--muted); font-size: 13px; margin-top: 40px; }
.empty { color: var(--muted); padding: 12px; }
"""

_DPO_CHECKS = (
    (
        "Retention",
        "How long does the observability backend keep traces? Align it with your "
        "record of processing activities.",
    ),
    (
        "Location",
        "Where is the backend hosted? Transfers outside the EU need a legal basis "
        "(adequacy decision or standard contractual clauses).",
    ),
    (
        "Processor agreement",
        "Is a data processing agreement (GDPR article 28) signed with the backend vendor?",
    ),
    ("Access", "Who can read traces? Restrict access to the people who need it and log it."),
    (
        "Pseudonym key",
        "Keep CAVIARD_HMAC_KEY in a secret manager. Rotating it breaks correlation "
        "with older traces.",
    ),
)
_SUGGESTIONS = {"mask": "add to keys.mask", "hash": "add to keys.hash"}


def render_html(summary: dict[str, Any]) -> str:
    """The complete HTML page for an audit summary."""
    records = summary["records"]
    total, affected = records["total"], records["affected"]
    share = f"{affected / total:.1%}" if total else "0%"
    findings = sum(entity["findings"] for entity in summary["entities"])
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Caviard audit report</title>",
        f"<style>{_CSS}</style></head><body><main>",
        _header(summary),
        '<section class="cards">',
        _card(f"{total:,}", "records analysed" + _kinds(records["by_kind"])),
        _card(f"{affected:,}", f"with personal data ({share})"),
        _card(f"{findings:,}", "findings"),
        _card(f"{len(summary['warnings']):,}", "warnings"),
        "</section>",
        _entities(summary["entities"]),
        _locations(summary["locations"], summary["more_locations"]),
        _groups(summary["services"], summary["scopes"]),
        _warnings(summary["warnings"]),
    ]
    if "examples" in summary:
        parts.append(_examples(summary["examples"]))
    parts += [
        "<h2>Proposed policy</h2>",
        '<p class="meta">Save it as <code>caviard.toml</code> (or merge its lists into your '
        "policy) and review it: the sample may not cover every case.</p>",
        f"<pre><code>{_e(summary['proposed_policy'])}</code></pre>",
        _dpo(),
        _footer("examples" in summary),
        "</main></body></html>",
    ]
    return "\n".join(parts) + "\n"


def _footer(examples: bool) -> str:
    extra = (
        ", plus the redacted examples requested with <code>--examples</code>" if examples else ""
    )
    return (
        "<footer><p>This report contains no analysed value: only counts, entity types and "
        f"names of attributes, services and instrumentations, themselves redacted{extra}. "
        "Detection is not perfect: names in free text are not detected, only values under "
        "field names such as <code>customer_name</code>.</p></footer>"
    )


def _header(summary: dict[str, Any]) -> str:
    files = ", ".join(
        f"{_e(f['name'])} ({_e(f['format'] or 'empty')}, {f['records']:,} records)"
        for f in summary["files"]
    )
    policy = summary["policy"]
    source = f" from {_e(policy['file'])}" if policy.get("file") else ""
    return (
        '<header><h1><span class="brand">Caviard</span> audit report</h1>'
        f'<p class="meta">Generated {_e(summary["generated_at"])} with caviard '
        f"{_e(summary['caviard_version'])}, policy preset "
        f"<code>{_e(policy['preset'])}</code>{source}.<br>Input: {files or 'none'}.</p>"
        "</header>"
    )


def _card(value: str, label: str) -> str:
    """A summary card; ``label`` is trusted HTML built by this module."""
    return (
        f'<div class="card"><div class="value">{_e(value)}</div>'
        f'<div class="label">{label}</div></div>'
    )


def _kinds(by_kind: dict[str, dict[str, int]]) -> str:
    if len(by_kind) < 2:
        return ""
    kinds = ", ".join(
        f"{_e(KIND_LABELS.get(kind, kind))} {data['records']:,}" for kind, data in by_kind.items()
    )
    return f" ({kinds})"


def _entities(entities: list[dict[str, Any]]) -> str:
    if not entities:
        return '<h2>Personal data found</h2><div class="panel"><p class="empty">None.</p></div>'
    top = max(entity["findings"] for entity in entities)
    rows = "".join(
        "<tr>"
        f'<td>{_e(entity["label"])}<br><span class="chip mono">{_e(entity["entity"])}</span></td>'
        f'<td class="num">{entity["findings"]:,}</td>'
        f'<td class="num">{entity["records"]:,}</td>'
        f"<td>{_action(entity['action'])}</td>"
        f'<td style="width:30%">{_bar(entity["findings"] / top)}</td></tr>'
        for entity in entities
    )
    return (
        "<h2>Personal data found</h2>"
        '<div class="panel"><table><thead><tr><th>Type</th><th class="num">Findings</th>'
        '<th class="num">Records</th><th>Policy action</th><th></th></tr></thead>'
        f"<tbody>{rows}</tbody></table></div>"
    )


def _bar(share: float) -> str:
    return f'<div class="bar" style="width:{100 * share:.1f}%"></div>'


def _action(action: str) -> str:
    if action == "keep":
        return '<span class="badge warn">keep (exported in clear)</span>'
    return f'<span class="badge">{_e(action)}</span>'


def _locations(locations: list[dict[str, Any]], more: int) -> str:
    if not locations:
        return ""
    rows = []
    for row in locations:
        source = row["source"] + (f" {row['detail']}" if row["detail"] else "")
        chips = "".join(
            f'<span class="chip mono">{_e(entity)} {count:,}</span>'
            for entity, count in row["findings"].items()
        )
        whole = f"{row['whole'] / row['affected']:.0%}" if row["affected"] else "-"
        suggestion = _SUGGESTIONS.get(row["suggestion"] or "")
        advice = f'<span class="badge">{_e(suggestion)}</span>' if suggestion else "-"
        rows.append(
            "<tr>"
            f'<td><code>{_e(row["key"])}</code><br><span class="source">{_e(source)}</span></td>'
            f'<td class="num">{row["affected"]:,} / {row["values"]:,}</td>'
            f"<td>{chips}</td>"
            f'<td class="num">{whole}</td>'
            f"<td>{_e(row['rule'] or '-')}</td>"
            f"<td>{advice}</td>"
            "</tr>"
        )
    tail = f'<p class="meta">{more:,} more location(s) in the JSON output.</p>' if more else ""
    return (
        "<h2>Where</h2>"
        '<p class="meta">Values with personal data out of all values seen at each location; '
        "<em>whole</em> is the share of those values that were one identifier from start to "
        "end, which a key rule can replace safely. Rule <em>field</em>: replaced because of its "
        "field name.</p>"
        '<div class="panel"><table><thead><tr><th>Location</th><th class="num">Values</th>'
        '<th>Findings</th><th class="num">Whole</th><th>Current rule</th><th>Suggestion</th>'
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>{tail}"
    )


def _groups(services: list[dict[str, Any]], scopes: list[dict[str, Any]]) -> str:
    if not services and not scopes:
        return ""
    return (
        '<h2>Services and instrumentations</h2><div class="grid2">'
        + _group_table("Service", services)
        + _group_table("Instrumentation", scopes)
        + "</div>"
    )


def _group_table(title: str, groups: list[dict[str, Any]]) -> str:
    if not groups:
        return f'<div class="panel"><p class="empty">No {_e(title.lower())} name.</p></div>'
    rows = "".join(
        f"<tr><td><code>{_e(group['name'])}</code></td>"
        f'<td class="num">{group["affected"]:,} / {group["records"]:,}</td>'
        f'<td class="num">{group["findings"]:,}</td></tr>'
        for group in groups
    )
    return (
        f'<div class="panel"><table><thead><tr><th>{_e(title)}</th>'
        '<th class="num">Records</th><th class="num">Findings</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></div>"
    )


def _warnings(warnings: list[dict[str, str]]) -> str:
    if not warnings:
        return ""
    items = "".join(f"<li>{_e(warning['message'])}</li>" for warning in warnings)
    return f'<h2>Warnings</h2><ul class="warnings">{items}</ul>'


def _examples(examples: dict[str, list[str]]) -> str:
    blocks = "".join(
        f'<h3><span class="chip mono">{_e(entity)}</span></h3>'
        + "".join(f"<p><code>{_e(snippet)}</code></p>" for snippet in snippets)
        for entity, snippets in sorted(examples.items())
        if snippets
    )
    return (
        "<h2>Examples, redacted</h2>"
        '<p class="caution">These excerpts are redacted, but the text around each finding may '
        "still hold data the detectors miss, such as names. Do not share this report outside "
        "your organisation.</p>" + (blocks or '<p class="empty">No example.</p>')
    )


def _dpo() -> str:
    items = "".join(
        f"<li><strong>{_e(title)}.</strong> {_e(text)}</li>" for title, text in _DPO_CHECKS
    )
    return (
        "<h2>Points to check with your DPO</h2>"
        f'<div class="note"><ul>{items}</ul><p class="meta">This checklist is not legal '
        "advice.</p></div>"
    )


def _e(value: object) -> str:
    return escape(str(value), quote=True)
