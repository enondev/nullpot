# ADR-004: Widenet Listener

## Status
Accepted

## Context
The Widenet listener is an all-port TCP/UDP trap using Linux SO_ORIGINAL_DST
to recover the original destination of redirected traffic. It must never
block on aggregator I/O — telemetry is pushed to a buffered channel.

## Decision
- `widenet.Listener` implements `core.TrapModule` (`Name()` returns "widenet",
  `Start(ctx, events)` binds a packet socket and reads datagrams).
- Each packet is converted to an OCSF `ThreatEvent` (class_uid 2004,
  category_uid 2, activity_id 1) with `src_endpoint.ip`/`port` set from the
  remote address and `finding_info.types` = ["port_scan"].
- Events are pushed to the shared `events` channel; the caller (sensor daemon)
  is responsible for non-blocking overflow handling via the shipper.
- SO_ORIGINAL_DST syscall application is documented as TODO pending
  platform-specific build tags (syscall.Handle typing differs by platform).

## Consequences
- Captures redirected trap traffic on all ports without knowing destinations
  ahead of time.
- Non-blocking: ReadFrom returns immediately on ctx cancellation.
