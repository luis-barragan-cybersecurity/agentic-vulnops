"""OpenTelemetry setup — live monitoring is on by default.

A console span exporter is wired by default so traces are visible with zero config; set
`OTEL_EXPORTER_OTLP_ENDPOINT` to ship spans to a collector instead (wired in the live
monitoring stand-up ticket). Idempotent: safe to call once per process.
"""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

_CONFIGURED = False

SERVICE_NAME = "ave"


def setup_tracing() -> trace.Tracer:
    """Configure the global tracer provider once and return an AVE tracer."""
    global _CONFIGURED
    if not _CONFIGURED:
        provider = TracerProvider(
            resource=Resource.create({"service.name": SERVICE_NAME})
        )
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
        trace.set_tracer_provider(provider)
        _CONFIGURED = True
    return trace.get_tracer(SERVICE_NAME)
