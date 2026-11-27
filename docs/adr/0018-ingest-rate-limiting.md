# ADR-018: Ingest Rate Limiting

## Status
Accepted

## Context
The aggregator ingest receiver `handleIngest` had no rate limiting. An attacker could flood `POST /v1/ingest` with millions of gzip JSON events, exhausting memory and CPU.

## Decision
- Add a per-IP token bucket rate limiter to `handleIngest`, applied before body decompression and parsing.
- Reject excess requests with HTTP 429 Too Many Requests.
- Default rate: 10 requests/second, burst 20.
- Per-IP state stored in a `sync.Mutex`-protected map.

## Consequences
- Legitimate sensor traffic (low volume, periodic) is unaffected.
- Attack floods are rejected at the edge with HTTP 429, protecting memory and CPU.
- Per-IP limiter map grows unbounded under very high source-IP cardinality; acceptable for MVP, bounded eviction may be added later.
