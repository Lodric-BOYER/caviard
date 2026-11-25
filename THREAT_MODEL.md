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
| Forgotten path | Exception events, status messages, links, trace state (set by the caller's `tracestate` header), resources, instrumentation scopes, OpenTelemetry log records (GenAI events), logging records and their private extra fields, LiteLLM payloads and the exceptions LiteLLM hands to its loggers, async streams logged by two threads at once (LiteLLM before 1.87.4), the assembled response that LiteLLM writes into the logging state after the async loggers of a streamed call ran (LiteLLM 1.108 and later). | The OpenTelemetry wrappers redact whole spans and log records; dedicated logging and LiteLLM integrations; loggers get redacted, frame-less copies of exceptions; LiteLLM 1.87.4 or later required, older versions flagged at run time; the state of a streamed async call redacted again when LiteLLM's sync handler runs; loggers that read LiteLLM's raw request before the call are flagged at run time. | OTLP protobuf encoding of spans and logs inspected byte by byte; LiteLLM pipeline run end to end, failures and async streams included. |
| Bare exporter | A second exporter or backend is added without Caviard. | Documentation; `caviard audit` on exports shows what leaks. | Audit tests. |
| Regular expression denial of service | A user input crafted to make a pattern backtrack, or dense with candidates that each cost a validation. | Bounded quantifiers, pre-filters, size cap per value (`max_chars`), at most 10,000 candidate matches per text; a text whose redaction does not settle in three passes, or a long text made largely of invisible or composed characters, is replaced whole. | 1 MB hostile inputs under 2.5 s. |
| Re-identification | Pseudonyms reversed by brute force over a small value space (phone numbers). | HMAC-SHA256 with a 32-byte key; the key never appears in any output. | Key absent from outputs; same value gives the same token only with the same key. |
| Leak by the library | A value printed in an error message, a warning or a report. | Error messages never quote values (invariant I3); the audit keeps counts and redacted names only. | Reports and CLI outputs searched for every test value. |
| Partial redaction | Part of a value stays in clear: the accented start of an email, the second word of a name (`customer_name=Camille Martin`), the rest of a nested repr, a secret under a compound name (`db_password`). | Unicode-aware patterns; whole-value replacement for sensitive field names, compound ones included; values after field names read up to the next field, a closing bracket or the line end, brackets balanced. | Detector tests with Unicode values; field values in logfmt, reprs, YAML and query strings. |
| Evasion by disguise | A value written with invisible characters (zero-width space, soft hyphen), fullwidth digits, no-break spaces, dashes or accents apart from their letter; a placeholder glued to a value (`[SECRET]hunter2`) or a key shaped like one (`[PASSWORD]`). | Patterns run on a normalised view of the text, mapped back to the original; a finding that touches a placeholder covers it, and only placeholders of real types are exempt. | Property tests on texts with disguised characters; idempotence fuzzing. |
| Evasion by structure | A value hidden where the walker does not look: a mapping key, a tuple, set or bytes inside a mapping, a list under a sensitive field name, JSON nested deeper than the parser accepts (a limit that depends on the Python version and the stack size) or encoded once more than `json.max_depth`, a payload printed inside a message (`f"args {args}"`, a dataclass, a logging argument), escaped characters. | Keys are redacted like values; unknown types, JSON nested deeper than 64 levels, too deep to parse or encoded too many times are replaced whole, never read as plain text; sensitive field names replace any value, also when written in text (`customer_name='...'`); JSON objects and Python dictionaries found in a text are walked; logging arguments are redacted one by one before they are merged. | Property tests with identifiers in keys and values of random structures; JSON nested from 100 to 100,000 levels, on every supported Python version; payloads quoted in texts and logging arguments. |
| Supply chain | A dependency or the package itself is compromised, as LiteLLM was on PyPI in March and October 2026. | No dependency in the core; compromised LiteLLM versions excluded; CI and release builds install nothing published in the last week; releases from tags through Trusted Publishing with attestations, only after the full CI passes on the tagged commit; actions pinned by commit; two-factor authentication. | CI: pip-audit, bandit, CodeQL, OpenSSF Scorecard. |
| False sense of security | A team believes its traces are anonymous. | Documented limitations and per-type recall from synthetic data; no promise of full coverage. | Documentation review. |

## Out of scope

- **Data in clear inside the process**, before export: memory dumps, debuggers, other
  libraries that log on their own.
- **Free-text names and addresses** without a field name: Caviard has no named-entity
  recognition. Plug a detector through the `caviard.detectors` entry point if you need it.
- **Some formats**: international numbers without `+`, a NIR split across two lines, card
  numbers without a related word, values encoded in base64.
- **LiteLLM hooks that run before redaction**: `log_pre_api_call` and `log_post_api_call`
  of other loggers, and the LiteLLM proxy's own hooks, receive raw data. Caviard warns;
  export those loggers' spans through `RedactingSpanExporter`.
- **A compromised host**: an attacker who can read the process memory or the environment
  can read the pseudonym key and the data.
- **Backends and their retention**: where traces are stored, for how long and who reads
  them remains your responsibility; the audit report lists the points to check.
- **Anonymisation in the GDPR sense**: pseudonymised data remains personal data.
