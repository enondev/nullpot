# ADR-015: Edge API (Cloudflare Worker)

## Status
Accepted

## Context
Cloudflare Edge serving <10ms GET /v1/ip/:ip, /v1/asn/:asn, /v1/edl/:feed.txt,
/v1/stix/bundle.json, /v1/misp/manifest.json backed by KV + D1.

## Decision
- `edge-api/src/routes/index.ts` handles all Edge API routes with KV-backed
  reads (<10ms), cache miss returns 404/empty (aggregator populates KV
  asynchronously).
- EDL returns plain-text blocklist (one IP per line) for firewall ingestion.
- STIX bundle served with `application/stix+json;version=2.1` content type.
- `edge-api/src/ai/index.ts` scheduled Workers AI summarizer, invoked only
  when high-severity events (score >= 75) are pending in KV.
- `edge-api/migrations/schema.sql` D1 schema for ip_reputation, asn_reputation,
  events, blocklist tables.

## Consequences
- Sub-10ms lookups via KV cache.
- Workers AI never invoked on low-severity events (free-tier guardrail).
- D1 stores historical events for analysis; KV serves hot lookups.
