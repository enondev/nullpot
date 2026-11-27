# ADR-008: Sensor Daemon

## Status
Accepted

## Context
The unified single-binary sensor daemon wires all TrapModules (widenet,
http_persona, ssh, raw_tcp) plus the non-blocking shipper exporter.

## Decision
- `sensors/cmd/sensor/main.go` registers modules, creates a bounded buffered
  channel (4096), starts each module in its own goroutine, starts the shipper
  (batch size 100, 5s flush timeout, gzip JSON POST to aggregator), and feeds
  channel events to the shipper.
- Channel overflow uses drop-oldest protection so attackers cannot stall the
  sensor.
- A `/healthz` endpoint serves on :8090 for observability.
- Graceful shutdown on SIGINT/SIGTERM via signal.NotifyContext.

## Consequences
- Single binary collects telemetry across all trap modules.
- Non-blocking hot path: listeners never block on aggregator I/O.
- Observability via health endpoint.
