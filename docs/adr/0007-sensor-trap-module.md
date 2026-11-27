# ADR-0007: Sensor Trap Module Architecture

## Status
Accepted

## Context
The sensor runs multiple trap modules (widenet, http_persona, ssh, raw_tcp)
that must all implement the `TrapModule` interface and push telemetry to a
shared buffered channel.

## Decision
- Each trap module implements `core.TrapModule` with `Name()` and
  `Start(ctx, events)` methods.
- Modules register themselves with the `core.Registry` at startup.
- The sensor daemon iterates the registry and starts each module in its own
  goroutine, all pushing to a shared buffered channel.
- Shipper handles non-blocking batch export to the aggregator.
- Each module has its own bounded channel overflow protection via
  drop-oldest semantics.

## Consequences
- Decoupled trap modules can be added/removed independently.
- Non-blocking hot path: listeners never block on aggregator I/O.
- Graceful shutdown via context cancellation.
