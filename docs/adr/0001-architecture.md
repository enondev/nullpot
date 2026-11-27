# ADR-001: Architecture

## Status
Accepted

## Context
nullpot is a Threat & Abuse Intelligence Platform. Sensors must never block on
network I/O to the central aggregator, captured payloads must never be
executed, and Cloudflare free-tier guardrails must be respected (no raw
firehose, batched KV/D1 writes, Workers AI only on confirmed high-severity
multi-stage attacks or novel exploit payloads).

## Decision
Architecture: Go Edge Sensors -> Central Go Correlation & Risk Scoring Engine ->
Cloudflare Edge (KV, D1, Workers AI).

- Every protocol engine implements `TrapModule` (`Name() string`,
  `Start(ctx context.Context, events chan<- ocsf.ThreatEvent) error`).
- Sensors push telemetry to a bounded, buffered channel with drop-oldest
  overflow protection; a non-blocking shipper exports to the aggregator.
- All captured payloads are hashed (SHA-256), static IOCs extracted, and
  quarantined — never executed.
- The aggregator performs stateful sliding-window aggregation, deduplication,
  and scoring in-memory before any Cloudflare sync.
- KV writes stay well under 1,000/day; D1 row writes stay well under
  100,000/day; Workers AI invoked only on confirmed high-severity multi-stage
  attacks or novel exploit payloads.
- IP/ASN enrichment uses `gaissmai/bart` prefix tables and memory-mapped
  `.mmdb` lookups (GeoLite2 free).

## Consequences
- Sensors cannot stall or fingerprint via blocking aggregator I/O.
- Legal guardrail: no execution of captured binaries/scripts.
- Cloudflare free-tier limits respected via batching and caps.
