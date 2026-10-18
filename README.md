# caviard

**Fail-closed redaction of personal data and secrets in AI agent traces and logs.**

Caviard masks personal data (French and EU identifiers validated by checksum, emails,
phone numbers, IBANs, API keys) in OpenTelemetry spans, Langfuse traces, LiteLLM logs
and Python logging records, *before* they leave your application. If redaction fails,
the span is quarantined or dropped, never exported in clear.

> Status: pre-alpha, under active development. Not yet published on PyPI.

License: Apache-2.0
