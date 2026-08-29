"""Live monitoring — on from the start.

Every run emits OpenTelemetry traces (a run is a trace; each phase is a span), which the
run record mirrors and future burn-rate monitoring reads. See `setup_tracing`.
"""

from ave.telemetry.otel import setup_tracing

__all__ = ["setup_tracing"]
