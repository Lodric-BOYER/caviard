"""HTML and text rendering: escaped, self-contained, readable."""

from __future__ import annotations

import re

from caviard.audit import Auditor, Field, Record, render_html, render_text


def _summary(**options: object) -> dict[str, object]:
    audit = Auditor(**options)  # type: ignore[arg-type]
    audit.add(
        Record(
            "span",
            service='<script>alert("x")</script>',
            scope="evil & co",
            fields=[
                Field("span", "<b>key</b>", "écrire à camille.martin@exemple.fr"),
                Field("event", "exception.message", "06 12 34 56 78", detail="<img src=x>"),
            ],
        )
    )
    audit.add(Record("log", fields=[Field("log", "body", "rien", attribute=False)]))
    return audit.summary()


def test_html_escapes_every_name() -> None:
    page = render_html(_summary())
    assert "<script" not in page
    assert "<img" not in page
    assert "<b>key</b>" not in page
    assert "&lt;b&gt;key&lt;/b&gt;" in page
    assert "evil &amp; co" in page


def test_html_is_self_contained() -> None:
    page = render_html(_summary())
    assert page.startswith("<!doctype html>")
    assert not re.search(r"<[^>]+\s(?:src|href)\s*=", page)  # no resource to fetch
    assert not re.search(r"url\(|@import|https?://", page)
    assert "prefers-color-scheme: dark" in page
    assert "Points to check with your DPO" in page
    assert "log records 1, spans 1" in page


def test_text_summary() -> None:
    text = render_text(_summary())
    assert text.startswith("caviard audit: 0 file(s), 2 record(s) (log records 1, spans 1)")
    assert "Personal data in 1 record(s) (50.0%)." in text
    assert "EMAIL" in text
    assert "camille" not in text


def test_text_summary_of_an_empty_audit() -> None:
    text = render_text(Auditor().summary())
    assert text == "caviard audit: 0 file(s), 0 record(s)\nPersonal data in 0 record(s)."


def test_text_summary_lists_the_top_locations() -> None:
    audit = Auditor()
    keys = [f"app.field{index}" for index in range(16)] + ["app.a" + "_long_name" * 6]
    audit.add(Record("span", fields=[Field("span", key, "mail x@exemple.fr") for key in keys]))
    text = render_text(audit.summary())
    assert "... 2 more location(s) in the HTML or JSON report" in text
    assert "  app.a_long_name_long_name_long_name_long_name_l... " in text  # cut at 50


def test_text_summary_lists_warnings() -> None:
    audit = Auditor()
    audit.add(Record("span", fields=[Field("span", "blob", b"\x00")]))
    assert render_text(audit.summary()).endswith(
        "Warnings:\n  - 1 binary value(s) were not analysed: they are replaced entirely at export."
    )
