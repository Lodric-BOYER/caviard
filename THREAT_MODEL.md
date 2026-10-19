# Threat model

Caviard is judged by its failures: this document lists what it protects, from whom, the
threats it addresses with their counter-measures and tests, and what remains out of reach.

## What is protected

- **Personal data in telemetry**: what users type into an AI agent (names, emails, phone
  numbers, social security numbers, IBANs, card numbers, addresses) and what tools return,
  as it flows into spans, logs and LLM gateway callbacks.
- **Secrets in telemetry**: API keys, bearer tokens, passwords, JWTs and private keys
  that end up in prompts, tool arguments, headers or error messages.
- **The pseudonym key**: whoever holds it can test guesses against pseudonyms.

## Trust boundaries

Caviard runs inside the application process, between the code that produces telemetry and
the exporter that sends it out. Everything before the exporter is trusted: it already holds
the data in clear. Everything after it (the network, the observability backend, its
vendor, the people with access to it, exported files) is where data must arrive redacted.

## Threats and counter-measures

| Threat | Scenario | Counter-measure | Test |
| --- | --- | --- | --- |
| Leak on error | A detector, a plugin or a malformed value raises, and the span leaves in clear. | Fail-closed: quarantine (only allowed attributes keep their value), then drop. | Simulated failures in every integration. |
| Forgotten path | Exception events, status messages, links, resources, logging records, LiteLLM payloads. | The OpenTelemetry wrapper redacts the whole span; dedicated logging and LiteLLM integrations. | OTLP protobuf encoding inspected byte by byte; LiteLLM pipeline run end to end. |
| Bare exporter | A second exporter or backend is added without Caviard. | Documentation; `caviard audit` on exports shows what leaks. | Audit tests. |
| Regular expression denial of service | A user input crafted to make a pattern backtrack. | Bounded quantifiers, pre-filters, size cap per value (`max_chars`). | 1 MB hostile inputs under 2.5 s. |
| Re-identification | Pseudonyms reversed by brute force over a small value space (phone numbers). | HMAC-SHA256 with a 32-byte key; the key never appears in any output. | Key absent from outputs; same value gives the same token only with the same key. |
| Leak by the library | A value printed in an error message, a warning or a report. | Error messages never quote values (invariant I3); the audit keeps counts and redacted names only. | Reports and CLI outputs searched for every test value. |
| Partial redaction | Part of a value stays in clear (for example the accented start of an email). | Unicode-aware patterns; whole-value replacement for sensitive field names. | Detector tests with Unicode values. |
| Evasion by nesting | A field hidden in JSON nested deeper than the parser accepts, a limit that depends on the Python version and the stack size. | Values nested deeper than 64 levels are replaced; JSON too deep to parse is replaced whole instead of being read as plain text. | JSON nested from 100 to 100,000 levels, on every supported Python version. |
| Supply chain | A dependency or the package itself is compromised, as LiteLLM was on PyPI in March 2026. | No dependency in the core; compromised LiteLLM versions excluded; releases from tags through Trusted Publishing with attestations; actions pinned by commit; two-factor authentication. | CI: pip-audit, bandit, CodeQL, OpenSSF Scorecard. |
| False sense of security | A team believes its traces are anonymous. | Documented limitations and per-type recall from synthetic data; no promise of full coverage. | Documentation review. |

## Out of scope

- **Data in clear inside the process**, before export: memory dumps, debuggers, other
  libraries that log on their own.
- **Free-text names and addresses** without a field name: Caviard has no named-entity
  recognition. Plug a detector through the `caviard.detectors` entry point if you need it.
- **A compromised host**: an attacker who can read the process memory or the environment
  can read the pseudonym key and the data.
- **Backends and their retention**: where traces are stored, for how long and who reads
  them remains your responsibility; the audit report lists the points to check.
- **Anonymisation in the GDPR sense**: pseudonymised data remains personal data.
