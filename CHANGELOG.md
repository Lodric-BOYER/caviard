# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project scaffolding: package layout, build configuration, test and lint tooling.
- Detection engine (standard library only): bounded regular expressions, checksum
  validation and context rules for French social security numbers (NIR), SIREN,
  SIRET, RPPS, IBAN, payment cards, French phone numbers, emails, IP addresses,
  API keys, bearer tokens, JWTs, private keys and credentials in URLs or assignments.
- Redaction actions per entity: mask, keyed pseudonym (HMAC-SHA256), partial, keep.
- JSON-aware redaction of nested and double-encoded tool arguments, with sensitive
  field names (`customer_name`, `email`, `iban`...) replaced entirely.
- Attribute key rules (allow, mask, hash, drop) for OpenTelemetry-style attributes.
- Policies as TOML, YAML or JSON files on top of presets (`standard`, `strict`,
  `debug-local`, `none`).
- Detector plugins through the `caviard.detectors` entry point group.
- `caviard scan` and `caviard keygen` commands.
- `caviard.otel.RedactingSpanExporter`: wraps any OpenTelemetry span exporter and
  exports redacted copies of span names, attributes, events, links, status
  messages and resource attributes. A span that cannot be redacted is quarantined
  or dropped (`on_error`).
- `caviard.integrations.langfuse.mask_otel_spans`: hook for the Langfuse SDK v5. Each
  span is handled on its own, so one failure never drops the whole export batch.
- `caviard.integrations.litellm.CaviardLogger`: LiteLLM callback that redacts
  messages, metadata, raw request and response bodies, the standard logging payload
  and responses (sync, async and streaming) before other callbacks see them, without
  touching the objects held by the application.
- `caviard.integrations.logging`: `RedactingFilter` for the standard `logging`
  module (message, arguments, exception, stack and extra fields), `install()` and a
  structlog processor.
- `caviard audit`: offline analysis of exported traces and logs (OTLP JSON from the
  OpenTelemetry Collector, JSON Lines, JSON arrays or text, optionally gzipped).
  Reports which personal data they hold, where (attribute keys, services,
  instrumentations), warnings such as allowed keys that expose data, and a proposed
  policy. Text, JSON and self-contained HTML outputs hold no analysed value;
  `--examples` adds redacted excerpts on request.
- `caviard policy check`: validates a policy file and shows its effective settings,
  with warnings for unknown entities, conflicting key rules and missing pseudonym keys.
- `caviard bench`: speed and identifier recall on synthetic French agent traces
  generated on the machine.
- Documentation: README in English and French, security policy (`SECURITY.md`) and
  threat model (`THREAT_MODEL.md`).
- Releases are built from version tags and published with PyPI Trusted Publishing; CI
  runs tests on Linux, Windows and macOS (Python 3.11 to 3.14), pip-audit, bandit,
  CodeQL and OpenSSF Scorecard.
