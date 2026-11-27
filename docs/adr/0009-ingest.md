# ADR-009: Ingest Receiver

## Status
Accepted

## Context
The aggregator needs an OpenAPI webhook receiver for sensor-to-aggregator
ingestion (gzip JSON POST /v1/ingest), plus canary callback listening and
OSINT/BGP pullers.

## Decision
- `ingest.Receiver` handles POST /v1/ingest with gzip decompression, accepts
  single ThreatEvent or batch JSON, validates via `ThreatEvent.Validate()`,
  writes to in-memory `EventStore`, and pushes to the processing channel.
- Invalid payloads return 400; accepted events return 202.
- Canary callback listener and OSINT/BGP pullers are scheduled components
  that respect rate limits (no raw firehose to Cloudflare).

## Consequences
- Sensors never block: shipper handles batching/retries.
- Aggregator validates before storing, preventing bad events from entering
  correlation.
- In-memory store enables zero-allocation lookups for correlation.
