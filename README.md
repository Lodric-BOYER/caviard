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
- **Fail-closed**: a span that cannot be redacted is quarantined or dropped, never
  exported in clear.
- **Traces stay useful**: model names, tool names and token counts stay in clear, JSON tool
  arguments are redacted field by field, and keyed pseudonyms (HMAC-SHA256) give the same
  token for the same user, so you can still follow a conversation.
- **Drop-in integrations**: OpenTelemetry, Langfuse (SDK v5), LiteLLM, `logging` and
  structlog.
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
# 'Mon numéro de sécu est [FR_NIR], mail [EMAIL:rf4y3edldfcv]'
```

Emails, phone numbers and IP addresses are pseudonymised by default. Give Caviard a stable
key, otherwise pseudonyms change at every restart:

```bash
caviard keygen                        # prints a new random key
export CAVIARD_HMAC_KEY="<that key>"  # keep it in a secret manager, never in your repository
```

### OpenTelemetry

Wrap your exporter: spans are redacted on the export thread, off the request path.

```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from caviard import Policy
from caviard.otel import RedactingSpanExporter

exporter = RedactingSpanExporter(OTLPSpanExporter(), Policy.load("caviard.toml"))
provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(exporter))
```

Span names, attributes, events (exception messages), links, status messages and resource
attributes are redacted. The original spans are never modified.

### Langfuse (SDK v5)

```python
from langfuse import Langfuse
from caviard.integrations.langfuse import mask_otel_spans

langfuse = Langfuse(mask_otel_spans=mask_otel_spans())
```

Each span is handled on its own, so one failure never drops a whole export batch.
Langfuse only lets this hook change span attributes; to also cover span names, events and
resources, pass `span_exporter=RedactingSpanExporter(...)` to `Langfuse`.

### LiteLLM

```python
import litellm
from caviard.integrations.litellm import CaviardLogger

litellm.callbacks = [CaviardLogger(), *other_callbacks]  # keep it first
```

Messages, metadata, raw request and response bodies, the standard logging payload and
responses (sync, async, streaming) are redacted before any other callback sees them. Your
application keeps the real response.

### Logging and structlog

```python
import logging
from caviard.integrations.logging import install

logging.basicConfig(level=logging.INFO)
install()  # adds a RedactingFilter to every handler of the root logger
```

For structlog, add `caviard.integrations.logging.structlog_processor()` to the processor
chain, after `format_exc_info` and before the renderer.

## Audit the traces you already have

```bash
caviard audit exports/ -o report.html --policy-out caviard.toml
```

```text
caviard audit: 2 file(s), 7 record(s) (JSON objects 2, spans 5)
Personal data in 7 record(s) (100.0%).

  type            findings   records  policy
  EMAIL                 22         6  hash
  REDACTED              10         5  replace
  IBAN                   5         5  mask

  where                                                      values  rule   suggestion
  llm.input_messages.*.message.content [span]                   5/5  -      -
  exception.message [event exception]                           5/5  -      -
  customer_contact [record]                                     1/1  -      hash
```

`caviard audit` reads OTLP JSON written by the OpenTelemetry Collector file exporter, JSON
Lines, JSON arrays (a Langfuse export, for example) and text, optionally gzipped. The
report shows which personal data your traces hold and where (attribute keys, services,
instrumentations), flags risky settings, proposes a policy and lists points to check with
your DPO. It holds counts, entity types and redacted attribute names only, never an
analysed value, so you can share it. `--examples N` adds redacted excerpts; the text
around them may hold names, so keep such a report internal.

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
sensitive_fields = ["client_name"]  # JSON fields whose value is always replaced

[pseudonym]
key_env = "CAVIARD_HMAC_KEY"   # or key_file = "/run/secrets/caviard_key"
```

| Preset | Use |
| --- | --- |
| `standard` (default) | Masks identifiers and secrets, pseudonymises emails, phones and IP addresses, keeps model and usage attributes readable. |
| `strict` | Everything masked, nothing pseudonymised; a span that fails redaction is dropped. |
| `debug-local` | Everything pseudonymised except secrets, for local debugging. |
| `none` | Start from scratch. |

Key rules win in this order: drop, mask, hash, allow. Other attributes go through the
detectors.

## Command line

| Command | What it does |
| --- | --- |
| `caviard scan "text"` | Shows what would be redacted: types and positions, never the values. |
| `caviard audit PATH...` | Offline audit of exported traces or logs, with an HTML or JSON report. |
| `caviard policy check FILE` | Validates a policy file and shows its effective settings. |
| `caviard bench` | Speed and recall on synthetic traces generated on your machine. |
| `caviard keygen` | Generates a pseudonym key. |

## How it works

1. **Detect.** Bounded regular expressions find candidates, then check digits (mod 97
   for NIR and IBAN, Luhn for cards, SIREN, SIRET and RPPS) and context words validate
   them: a 9-digit number is a SIREN only near words such as "SIREN" or "société".
   Overlaps go to the most specific finding.
2. **Replace.** Each type has an action: mask, pseudonymise (HMAC-SHA256 with your key,
   normalised so that `06 12 34 56 78` and `+33 6 12 34 56 78` share a token), partial
   or keep. JSON strings, including double-encoded tool arguments, are redacted field by
   field.
3. **Never leak on error.** If anything fails, integrations quarantine the record (only
   allowed attributes keep their value) or drop it.

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
- **Recall figures come from synthetic data**; real traces are messier.
- **Attribute names are exported unchanged.** `caviard audit` warns when a name holds
  personal data.
- **LiteLLM:** on async calls that fail, legacy string callbacks such as `"langfuse"` in
  `litellm.failure_callback` run before Caviard, so register loggers as `CustomLogger`
  instances. Exception objects are not modified; their text is redacted in the traceback
  and the logging payload.
- **Speed:** a few megabytes per second per core. Redact on the export thread
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
