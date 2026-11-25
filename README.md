# Caviard

[![CI](https://github.com/Lodric-BOYER/caviard/actions/workflows/ci.yml/badge.svg)](https://github.com/Lodric-BOYER/caviard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/caviard)](https://pypi.org/project/caviard/)
[![Python](https://img.shields.io/pypi/pyversions/caviard)](https://pypi.org/project/caviard/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/Lodric-BOYER/caviard/blob/main/LICENSE)

**Fail-closed redaction of personal data and secrets in AI agent traces and logs.**

Agent traces hold what your users typed: names, emails, phone numbers, social security
numbers, IBANs, API keys. They are then shipped to an observability backend such as
Langfuse, Datadog or any OTLP endpoint, often outside the EU. Caviard redacts them at
export time, before they leave your process.

- **French and EU identifiers, validated**: NIR (French social security number, Corsica
  included), SIREN, SIRET, RPPS, IBAN, payment cards and French phone numbers, plus emails,
  IP addresses, API keys, bearer tokens, JWTs, private keys and credentials. Check digits
  (mod 97, Luhn) and context words keep false positives low.
- **Fail-closed**: a span or log record that cannot be redacted is quarantined or
  dropped, never exported in clear.
- **Traces stay useful**: model names, tool names and token counts stay in clear, JSON tool
  arguments are redacted field by field, and keyed pseudonyms (HMAC-SHA256) give the same
  token for the same user, so you can still follow a conversation.
- **Drop-in integrations**: OpenTelemetry (spans and logs), Langfuse (SDK v5), LiteLLM,
  `logging` and structlog.
- **Offline audit** of the traces you already have: `caviard audit export.jsonl -o report.html`.
- **No dependency** in the core (standard library only). Apache-2.0.

> **Status: alpha (0.1).** Detection relies on patterns, check digits and context: names
> in free text are not detected (no named-entity recognition), only values under field
> names such as `customer_name`. Read the [limitations](#limitations).

[Version française](https://github.com/Lodric-BOYER/caviard/blob/main/README.fr.md)

## Install

```bash
pip install caviard                 # core and command line, no dependency
pip install "caviard[otel]"         # OpenTelemetry exporter wrapper
pip install "caviard[langfuse]"     # Langfuse SDK v5 hook
pip install "caviard[litellm]"      # LiteLLM callback
pip install "caviard[yaml]"         # YAML policy files
```

Python 3.11 to 3.14.

## Quick start

```python
import caviard

caviard.redact("Mon numéro de sécu est 1 85 03 75 112 345 94, mail jean.dupont@exemple.fr")
# 'Mon numéro de sécu est [FR_NIR], mail [EMAIL:rf4y3edldfcv]'  (the token depends on the key)
```

Emails, phone numbers and IP addresses are pseudonymised by default. Give Caviard a stable
key, otherwise pseudonyms change at every restart:

```bash
caviard keygen                        # prints a new random key
export CAVIARD_HMAC_KEY="<that key>"  # keep it in a secret manager, never in your repository
```

### OpenTelemetry

Wrap your exporters: spans and log records are redacted on the export thread, off the
request path. The examples use the OTLP/HTTP exporters
(`pip install opentelemetry-exporter-otlp-proto-http`).

```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from caviard.otel import RedactingSpanExporter

exporter = RedactingSpanExporter(OTLPSpanExporter())  # default policy
provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(exporter))
```

Span names, attributes, events (exception messages), links, status messages, trace state,
resource and instrumentation scope attributes are redacted. The original spans are never
modified. To apply your own policy, pass it as second argument:
`RedactingSpanExporter(OTLPSpanExporter(), Policy.load("caviard.toml"))`.

Caviard only protects the exporters it wraps: wrap each of them, including a console
exporter or a second backend added later, and check a sample export with `caviard audit`.

GenAI instrumentations can also send prompts and completions as log events: wrap the log
exporter too (opentelemetry-sdk 1.39 or later). Bodies, attributes, event names and
resources are redacted.

```python
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

from caviard.otel import RedactingLogExporter

exporter = RedactingLogExporter(OTLPLogExporter())
logger_provider = LoggerProvider()
logger_provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
```

### Langfuse (SDK v5)

```python
from langfuse import Langfuse
from caviard.integrations.langfuse import mask_otel_spans

langfuse = Langfuse(mask_otel_spans=mask_otel_spans())
```

Each span is handled on its own, so one failure never drops a whole export batch.
Langfuse only lets this hook change span attributes. To also cover span names, events and
resources, give Langfuse a wrapped exporter. Langfuse then no longer sets the endpoint
and the credentials itself:

```python
import base64
import os

from langfuse import Langfuse
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

from caviard.otel import RedactingSpanExporter

base_url = os.environ.get("LANGFUSE_BASE_URL", "https://cloud.langfuse.com")
credentials = f"{os.environ['LANGFUSE_PUBLIC_KEY']}:{os.environ['LANGFUSE_SECRET_KEY']}"
exporter = OTLPSpanExporter(
    endpoint=f"{base_url}/api/public/otel/v1/traces",
    headers={
        "Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
        "x-langfuse-ingestion-version": "4",
    },
)
langfuse = Langfuse(span_exporter=RedactingSpanExporter(exporter))
```

### LiteLLM

```python
import litellm
from caviard.integrations.litellm import CaviardLogger

litellm.callbacks = [CaviardLogger(), *other_callbacks]  # keep it first
litellm.redact_messages_in_exceptions = True  # LiteLLM quotes the messages in its errors
```

Messages, metadata, raw request and response bodies, the standard logging payload and
responses (sync, async, streaming) are redacted before the logging callbacks see them. On
failure, loggers receive a copy of the exception of the same class, its text redacted.
Your application keeps the real response and the real exception.

LiteLLM hands the raw request to the `log_pre_api_call` and `log_post_api_call` hooks of
every logger before any redaction can run, and the LiteLLM proxy hands raw requests and
responses to its own hooks. Caviard warns once when a registered logger implements those
two hooks. For LiteLLM's OpenTelemetry loggers, export through Caviard as well, which
covers every span whatever the hook:

```python
from litellm.integrations.opentelemetry import OpenTelemetry, OpenTelemetryConfig
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

from caviard.otel import RedactingSpanExporter

config = OpenTelemetryConfig(exporter=RedactingSpanExporter(OTLPSpanExporter()))
litellm.callbacks = [CaviardLogger(), OpenTelemetry(config=config)]
```

LiteLLM 1.87.4 or later is required: earlier versions run the async and sync loggers of a
streamed call at the same time, so a logger could read the data before it is redacted.
The `litellm` extra also excludes 1.107.0, a release that was compromised on PyPI. For
async calls, redaction runs on the event loop (a few milliseconds per call).

With the LiteLLM proxy, reference the callback from the proxy configuration:

```python
# custom_callbacks.py, next to config.yaml
from caviard.integrations.litellm import CaviardLogger

caviard_logger = CaviardLogger.from_policy("caviard.toml")
```

```yaml
litellm_settings:
  callbacks: custom_callbacks.caviard_logger  # first, if you list other loggers
  redact_messages_in_exceptions: true
```

### Logging and structlog

```python
import logging
from caviard.integrations.logging import install

logging.basicConfig(level=logging.INFO)
install()  # adds a RedactingFilter to every handler of the root logger
```

Each argument of a message is redacted on its own before it is merged, dictionaries field
by field, then the merged message, the exception, the stack and the `extra` fields
(private ones too when they hold plain data, as some handlers export them). For
structlog, add `caviard.integrations.logging.structlog_processor()` to the processor
chain, after `format_exc_info` and before the renderer.

## Audit the traces you already have

```bash
caviard audit exports/ -o report.html --policy-out proposed.toml
```

```text
caviard audit: 2 file(s), 7 record(s) (JSON objects 2, spans 5)
Personal data in 7 record(s) (100.0%).

  type            findings   records  policy
  EMAIL                 12         7  hash
  IBAN                   5         5  mask
  REDACTED               2         2  replace

  where                                                      values  rule   suggestion
  llm.input_messages.*.message.content [span]                   5/5  -      -
  exception.message [event exception]                           5/5  -      -
  customer_contact [record]                                     2/2  -      hash
  customer_name [record]                                        2/2  field  -
```

`caviard audit` reads OTLP JSON written by the OpenTelemetry Collector file exporter, JSON
Lines, JSON arrays (a Langfuse export, for example) and text, optionally gzipped.
Directories are read recursively, and patterns such as `"exports/**/*.jsonl"` are
expanded even where the shell does not (PowerShell). The report shows which personal data
your traces hold and where (attribute keys, services, instrumentations), flags risky
settings, proposes a policy and lists points to check with your DPO. It holds counts,
entity types and redacted names (attributes, services, files) only, never an analysed
value, so you can share it; error messages redact file names too. `--examples N` adds redacted excerpts; the text around them
may hold names, so keep such a report internal. `--json` prints the summary as JSON, with
a `schema_version`. `--policy-out` writes a new file: it never replaces an existing one
without `--force`, and no output ever replaces an input. With `--check`, the exit status
is 1 when personal data is found, and also when values could not be analysed (too large,
binary): not analysed is not clean. A JSON document is read at once up to 64 MB; export
larger ones as JSON Lines. Lines longer than 16 MB are skipped and reported.

## Policies

A policy is a TOML, YAML or JSON file on top of a preset. Lists add to the preset; other
values replace it. `caviard policy check caviard.toml` shows the result.

```toml
version = 1
preset = "standard"            # standard, strict, debug-local or none

[entities]
FR_NIR = "mask"                # [FR_NIR]
EMAIL = "hash"                 # [EMAIL:rf4y3edldfcv], same email, same token
IBAN = "partial"               # [IBAN:...0189]
IP_ADDRESS = "keep"            # detector off

[keys]                         # attribute keys, glob patterns
allow = ["app.request_id"]     # exported unchanged
mask = ["app.customer.*"]      # replaced as a whole: [REDACTED]
hash = ["app.user_id"]         # pseudonymised as a whole
drop = ["http.request.body"]   # removed

[json]
sensitive_fields = ["numero_dossier"]  # field names whose value is always replaced

[pseudonym]
key_env = "CAVIARD_HMAC_KEY"   # or key_file = "/run/secrets/caviard_key"
```

| Preset | Use |
| --- | --- |
| `standard` (default) | Masks identifiers and secrets, pseudonymises emails, phones and IP addresses, keeps model and usage attributes readable. |
| `strict` | Everything masked, nothing pseudonymised; a span that fails redaction is dropped. |
| `debug-local` | Every detected identifier pseudonymised (secrets and JWTs still masked), for local debugging. |
| `none` | Start from scratch. |

Key rules win in this order: drop, mask, hash, allow. Other attributes go through the
detectors.

| Setting | Default (`standard`) | Meaning |
| --- | --- | --- |
| `version` | required | Policy format version: `1`. |
| `preset` | `"standard"` | Base preset: `standard`, `strict`, `debug-local` or `none`. |
| `on_error` | `"quarantine"` | When redaction fails: `quarantine` (only allowed attributes keep their value) or `drop`. |
| `max_chars` | `200000` | Longer values are replaced whole by `[TOO_LARGE]` (1,000 to 100,000,000). |
| `default_action` | `"mask"` | Action of the types without an `[entities]` rule: `mask`, `hash` or `partial`. |
| `plugins` | `true` | Load the detectors registered under the `caviard.detectors` entry point. |
| `[entities]` | emails, phones and IP addresses `hash` | Per type: an action (`mask`, `hash`, `partial`, `keep` to turn the detector off) or a table with `action`, `min_score` (0 to 1) and `keep_last` (1 to 8, for `partial`). |
| `[keys]` | model, usage and service attributes allowed; captured secret headers masked, in both spellings (`x-api-key`, `x_api_key`) | `allow`, `mask`, `hash` and `drop` lists of attribute key patterns (`*` matches any text, dots included; case-sensitive). |
| `[json] max_depth` | `4` | Levels of JSON encoded in strings that are decoded and walked (0 to 16). Beyond, a JSON document is replaced whole; `0` reads JSON as plain text. |
| `[json] sensitive_fields` | names, emails, phones, addresses, birth dates, IBAN, NIR, card data, passwords, secrets, tokens, API keys, cookies, compound names included (`billing_address`, `db_password`) | Field names whose value is always replaced, in JSON, in Python values and in text (`customer_name='...'`, `address: ...`). Case, accents and separators are ignored: `Prénom`, `prenom` and `pré-nom` are the same name. `*` matches any text: `"*_dossier"`. |
| `[pseudonym] key_env` | `"CAVIARD_HMAC_KEY"` | Environment variable holding the key. |
| `[pseudonym] key_file` | none | File holding the key; preferred to `key_env` when set. |
| `[pseudonym] length` | `12` | Token length (8 to 32). |

Rotating the pseudonym key changes every token: values pseudonymised with the old key can
no longer be linked to the new ones. Keep the old key as long as you need to correlate
past traces, and never reuse a key across environments that must stay unlinkable.

## Command line

| Command | What it does |
| --- | --- |
| `caviard scan "text"` | Shows what would be redacted: types and positions, never the values. |
| `caviard audit PATH...` | Offline audit of exported traces or logs, with an HTML or JSON report. |
| `caviard policy check FILE` | Validates a policy file and shows its effective settings. |
| `caviard bench` | Speed and recall per type on synthetic traces generated on your machine. |
| `caviard keygen` | Generates a pseudonym key. |

## How it works

1. **Detect.** Bounded regular expressions find candidates, then check digits (mod 97
   for NIR and IBAN, Luhn for cards, SIREN, SIRET and RPPS) and context words validate
   them: a 9-digit number is a SIREN only near words such as "SIREN" or "société".
   Overlaps go to the most specific finding. In plain text, values written after a
   sensitive field name are found too (`customer_name='...'`, `address: ...`, logfmt,
   query strings, Python reprs, JSON cut short), whole: up to the next field, a closing
   bracket or the line end, including inside the values of other fields
   (`url=...?token=...`). JSON objects or Python dictionaries quoted in a message are read
   field by field. Disguised characters hide nothing: invisible characters (zero-width
   space, soft hyphen), fullwidth digits, no-break spaces, dashes and accents written apart
   from their letter are normalised before detection, and escaped characters (`\u00e9` in
   JSON, `\xe9` in Python bytes) do not hide an email address.
2. **Replace.** Each type has an action: mask, pseudonymise (HMAC-SHA256 with your key,
   normalised so that `06 12 34 56 78` and `+33 6 12 34 56 78` share a token), partial
   or keep. JSON strings, including double-encoded tool arguments, are redacted field by
   field, keys included. What cannot be inspected is replaced whole: values of other
   types (bytes, objects), JSON nested deeper than 64 levels, too deep to parse or encoded
   more than `json.max_depth` times. Placeholders already in a text are kept, but never
   shield a value glued to them (`[SECRET]hunter2`).
3. **Never leak on error.** If anything fails, integrations quarantine the record (only
   allowed attributes keep their value) or drop it. A text holding more than 10,000
   candidate matches is replaced whole, which bounds the time spent on hostile inputs; so
   is a text built so that its redaction never settles.

Six invariants are each covered by tests: fail-closed; idempotent (redacting twice
changes nothing); silent (no analysed value in errors, logs or reports); bounded time
(1 MB hostile inputs in under 2.5 s, values over `max_chars` replaced whole); the
pseudonym key never appears in any output; readable (model names, tool names and token
counts stay in clear).

## Limitations

- **No named-entity recognition.** Names, postal addresses or health details in free
  text are not detected; they are only replaced under field names such as
  `customer_name` or `address`. You can add detectors through the `caviard.detectors`
  entry point.
- **Context is required for some numbers.** Card numbers, SIREN, SIRET and RPPS are only
  reported near related words, which avoids false positives on order or trace numbers.
- **Some formats are not detected:** international numbers without `+` (`33612345678`), a
  NIR split across two lines, values encoded in base64.
- **Field names are read generously.** A value after a sensitive name is replaced in prose
  (`email : see below`) and in code (`token = make_token()`) too; flags, nulls and type
  annotations (`password: str`) are left alone.
- **Recall figures come from synthetic data.** `caviard bench` reports them per type, in
  the formats its generator writes; real traces are messier.
- **Attribute names are exported unchanged** (keys inside values are redacted).
  `caviard audit` warns when a name holds personal data.
- **LiteLLM:** on async calls that fail, legacy string callbacks such as `"langfuse"` in
  `litellm.failure_callback` run before Caviard, so register loggers as `CustomLogger`
  instances. The exception copy handed to loggers has no frames (they hold local
  variables): its stack trace is attached as redacted text instead. Loggers that implement
  `log_pre_api_call` or `log_post_api_call` receive the raw request (Caviard warns). On
  streamed async calls, LiteLLM writes the assembled response into the logging state after
  the async loggers ran, and Caviard redacts it again a few milliseconds later: a logger
  that keeps `kwargs` to read it later should copy what it needs in its callback.
- **Speed:** about 1 to 3 MB/s per core, less on short texts dense with identifiers
  (`caviard bench` measures it on your machine). Redact on the export thread
  (`BatchSpanProcessor`), not on the request path.
- **Pseudonymised data is still personal data** under the GDPR. Caviard reduces what
  leaves your systems; it does not make traces anonymous.

## Security

Report vulnerabilities privately, as explained in
[SECURITY.md](https://github.com/Lodric-BOYER/caviard/blob/main/SECURITY.md). The threat
model is in [THREAT_MODEL.md](https://github.com/Lodric-BOYER/caviard/blob/main/THREAT_MODEL.md).

## Development

```bash
uv venv && uv pip install -e . --group dev
pytest
ruff check . && ruff format --check . && mypy
```

Tests only use synthetic data (Faker and generated identifiers), never real personal data.

## License

[Apache-2.0](https://github.com/Lodric-BOYER/caviard/blob/main/LICENSE)
