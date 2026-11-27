# ADR-013: Cloudflare Free-Tier Guardrails

## Status
Accepted

## Context
Cloudflare free tier limits: ~1,000 KV writes/day, ~100,000 D1 row writes/day,
Workers AI only on confirmed high-severity multi-stage attacks or novel
payloads. No raw scanner/BGP firehose to Cloudflare.

## Decision
- `cloudflare.KVUploader` enforces daily write cap (default 1,000) with
  per-day reset; WriteBatch rejects batches that would exceed cap.
- `cloudflare.D1Writer` enforces daily row cap (default 100,000) with
  per-day reset.
- `cloudflare.Sync` coordinates KV + D1 batches; returns per-component results
  and errors.
- Aggregator performs sliding-window aggregation/dedup/scoring in-memory
  first; only critical-risk events synced to Cloudflare.
- Workers AI (edge-api/src/ai) invoked only when high-severity pending events
  exist in KV (score >= 75).

## Consequences
- Free-tier limits never exceeded; sync degrades gracefully when caps reached.
- No raw firehose to Cloudflare — only aggregated, scored snapshots.
- Batch caps enforced in code, not just convention.
