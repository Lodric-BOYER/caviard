"""Integrations with observability and LLM tooling.

Each module imports its third-party package lazily, so importing one
integration never requires the others:

- ``caviard.integrations.langfuse``: ``mask_otel_spans`` hook for the Langfuse SDK (v5).
- ``caviard.integrations.litellm``: ``CaviardLogger`` callback for LiteLLM.
- ``caviard.integrations.logging``: filter for the standard ``logging`` module and a
  structlog processor.

The generic OpenTelemetry exporter wrapper lives in ``caviard.otel``.
"""
