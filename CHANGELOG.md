# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project scaffolding: package layout, build configuration, test and lint tooling.
- Detection engine (standard library only): bounded regular expressions, checksum
  validation and context rules for French social security numbers (NIR), SIREN,
  SIRET, RPPS, IBAN (lowercase or hyphenated included), payment cards, French phone
  numbers (`(+33)` included), emails (escaped characters included), IP addresses, API
  keys (OpenAI, Anthropic, AWS, GitHub, Slack, Stripe, Google, Hugging Face, Groq, xAI,
  GitLab, PyPI, npm and others), bearer, basic and token authorization schemes, JWTs, PEM
  and PGP private keys, and credentials in URLs or assignments (`DB_PASSWORD=...`,
  `AWS_SECRET_ACCESS_KEY=...`). Disguised characters (zero-width and other invisible
  characters, fullwidth forms, no-break spaces, dashes, accents written apart from their
  letter) are normalised before detection. A text with more than 10,000 candidate
  matches is replaced whole, which bounds the time spent on hostile inputs.
- In plain text, values written after a sensitive field name (`customer_name='...'`,
  `address: ...`, logfmt, query strings, Python reprs, JSON cut short) are replaced
  whole, up to the next field, a closing bracket or the line end, also inside the values
  of other fields (`url=...?token=...`); a value that a detector finds whole keeps the
  detector's type. JSON objects or Python dictionaries quoted in a message are redacted
  field by field. Placeholders already in a text never shield a value glued to them.
- Redaction actions per entity: mask, keyed pseudonym (HMAC-SHA256), partial, keep.
- JSON-aware redaction of nested and double-encoded tool arguments, with sensitive
  field names (`customer_name`, `email`, `iban`...) replaced entirely, whatever their
  value. The default names include compound ones (`billing_address`, `contact_email`,
  `db_password`, `x-api-key`), and policies can use `*` patterns. Mapping keys are
  redacted like values; values that cannot be inspected (bytes, other objects, JSON too
  deep or encoded too many times) are replaced whole. Redacted JSON never grows past
  `max_chars` and keeps escaped any lone surrogate, which exporters cannot encode.
- Attribute key rules (allow, mask, hash, drop) for OpenTelemetry-style attributes.
  Captured HTTP headers that hold secrets are masked whatever the instrumentation's
  spelling (`x-api-key`, `x_api_key`).
- Policies as TOML, YAML or JSON files on top of presets (`standard`, `strict`,
  `debug-local`, `none`).
- Detector plugins through the `caviard.detectors` entry point group.
- `caviard scan` and `caviard keygen` commands.
- `caviard.otel.RedactingSpanExporter`: wraps any OpenTelemetry span exporter and
  exports redacted copies of span names, attributes, event names and attributes, links,
  status messages, trace state, resource and instrumentation scope attributes. A span
  that cannot be redacted is quarantined or dropped (`on_error`).
- `caviard.otel.RedactingLogExporter`: the same for OpenTelemetry log records (bodies,
  attributes, event names and resources), where GenAI instrumentations put prompts and
  completions (opentelemetry-sdk 1.39 or later).
- `caviard.integrations.langfuse.mask_otel_spans`: hook for the Langfuse SDK v5. Each
  span is handled on its own, so one failure never drops the whole export batch.
- `caviard.integrations.litellm.CaviardLogger`: LiteLLM callback (LiteLLM 1.87.4 or
  later, except 1.107.0, which was compromised on PyPI) that redacts messages, metadata,
  raw request and response bodies, the standard logging payload and responses (sync,
  async and streaming) before other callbacks see them, without touching the objects held
  by the application. The logging state of a streamed async call is redacted again once
  LiteLLM has written the assembled response into it, which LiteLLM 1.108 and later do
  after the async loggers ran. On failure, loggers get a copy of the exception of the
  same class, with redacted texts and no frames. It warns when an older LiteLLM is
  installed, and when a registered logger implements `log_pre_api_call` or
  `log_post_api_call`, which LiteLLM calls with raw data.
- `caviard.integrations.logging`: `RedactingFilter` for the standard `logging`
  module (message, arguments redacted one by one, exception, stack and extra fields,
  private ones included when they hold plain data), `install()` and a structlog
  processor.
- `caviard audit`: offline analysis of exported traces and logs (OTLP JSON from the
  OpenTelemetry Collector, JSON Lines, JSON arrays or text, optionally gzipped; files,
  directories read recursively, or glob patterns with `**`). Reports which personal data
  they hold, where (attribute keys, services, instrumentations), warnings such as allowed
  keys that expose data or files that are not valid JSON, and a proposed policy. Text,
  JSON (with a `schema_version`) and self-contained HTML outputs hold no analysed value,
  file names included, and names from the data are printed with control and
  bidirectional characters escaped; `--examples` adds redacted excerpts on request.
  Span event names and log event names are analysed too. `--policy-out` never replaces an
  existing file without `--force`, and no output replaces an input. `--check` fails when
  values could not be analysed. Memory stays bounded: JSON documents up to 64 MB, lines up
  to 16 MB (longer ones are skipped and reported).
- `caviard policy check`: validates a policy file and shows its effective settings,
  with warnings for unknown entities, conflicting key rules and missing pseudonym keys.
  The library warns as well when a policy names a type that no detector reports.
- `caviard bench`: speed and per-type recall on synthetic French agent traces generated
  on the machine.
- The command line prints warnings and errors on one line, with file names redacted,
  reads a file reached twice (through a symbolic link) once, and ends quietly when its
  output pipe is closed (`| head`).
- Documentation: README in English and French, security policy (`SECURITY.md`) and
  threat model (`THREAT_MODEL.md`).
- Releases are built from pushed version tags, without caches, after the full CI passes
  on the tagged commit, and published with PyPI Trusted Publishing; a manual run can only
  publish to TestPyPI. CI runs the tests on Linux and Windows (Python 3.11 to 3.14) and
  macOS (Python 3.13), pip-audit, bandit, CodeQL and OpenSSF Scorecard. CI and release
  builds install nothing published in the last week (uv `exclude-newer`), except for the
  dependency audit, which checks the latest releases. Dependabot waits a week before
  proposing a new release of an action.
