"""Offline audit of exported traces and logs (``caviard audit``).

The audit reads OTLP JSON, JSON Lines or text exports, runs the redaction
engine on every value and reports counts, entity types and redacted key names.
No analysed value ever reaches a summary or a report.
"""

from caviard.audit.auditor import ENTITY_LABELS, Auditor, propose_policy
from caviard.audit.html import render_html
from caviard.audit.readers import FORMATS, Field, FileStats, Record, read
from caviard.audit.text import render_text

__all__ = [
    "ENTITY_LABELS",
    "FORMATS",
    "Auditor",
    "Field",
    "FileStats",
    "Record",
    "propose_policy",
    "read",
    "render_html",
    "render_text",
]
