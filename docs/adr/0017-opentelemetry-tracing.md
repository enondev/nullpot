# ADR-0017: OpenTelemetry Tracing

## Status
Accepted

## Context
The nullpot system requires distributed tracing across sensor→aggregator→edge
API to correlate telemetry events across the full attack lifecycle. Previously,
the tracing package was a no-op stub with no actual export mechanism.

## Decision
- Use OpenTelemetry Go SDK with OTLP HTTP exporter for trace export.
- Trace context propagated via W3C TraceContext propagator across HTTP
  boundaries (sensor→aggregator→edge API).
- Trace context includes service name, version, and deployment environment as
  resource attributes.
- Sampling rate of 10% by default to limit overhead.
- Sensors pass trace context via HTTP headers to the aggregator; aggregator
  propagates to Cloudflare Worker edge API.

## Consequences
- Full end-to-end trace visibility from sensor capture through correlation
  scoring to edge API reputation lookup.
- Trace data exported to configured OTLP endpoint (Jaeger, Tempo, etc.).
- No secrets or PII exported in trace attributes (canary token IDs are decoy
  values by design).
- Graceful degradation: if OTLP endpoint is unreachable, spans are dropped
  without affecting sensor operation.
