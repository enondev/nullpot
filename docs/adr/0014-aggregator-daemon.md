# ADR-014: Aggregator Daemon

## Status
Accepted

## Context
Central ingestion, correlation, and CF sync daemon wiring ingest, correlate,
scoring, abuse, and cloudflare packages.

## Decision
- `aggregator/cmd/aggregator/main.go` wires all components, starts ingest
  receiver on :8081, processes events from a bounded channel (8192).
- Event processing: allowlist check -> correlation -> risk scoring -> XARF
  dispatch -> Cloudflare sync (critical only).
- Graceful shutdown on SIGINT/SIGTERM; health endpoint on :8091.
- Cloudflare sync optional (only when credentials provided).

## Consequences
- Single daemon handles the full correlation pipeline.
- Cloudflare sync only for critical events, respecting free-tier caps.
- Observability via health endpoint and structured logging.
