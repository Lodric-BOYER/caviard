# Caviard: project rules for Claude Code

Caviard redacts personal data and secrets from AI agent traces and logs at export
time. The full design notes (private, not versioned) live in `notes/conception.md`
when the file is present.

## Invariants (non-negotiable, each one covered by a test)
- I1 fail-closed: no unprocessed value is ever exported; on error, quarantine, then drop.
- I2 idempotence: redacting twice gives the same result as redacting once.
- I3 silence: no analysed value in error messages, logs or reports.
- I4 bounded time: bounded regex quantifiers, mandatory pre-filters, size cap, 1 MB tests.
- I5 correlation: same HMAC key, same pseudonym; the key never appears in any output.
- I6 readability: tool names, model names and token counts stay in clear.

## Code rules
- Core (`src/caviard/core`): standard library only, no dependency.
- Third-party packages are imported only in `caviard.otel` and `caviard.integrations.*`.
- No real personal data in the repository: Faker `fr_FR` and synthetic templates only.
- Every change comes with its test; pytest, ruff and mypy must pass.
- Comments and docstrings in English, concise, one block per idea (no line-by-line comments).
- One step at a time: the next one starts only when the test suite is green.

## Commands
- Install: `uv venv && uv pip install -e . --group dev` (or `pip install -e . --group dev`, pip 25.1+)
- Test: `pytest`
- Check: `ruff check . && ruff format --check . && mypy`
