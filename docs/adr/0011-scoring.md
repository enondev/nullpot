# ADR-011: Risk Scoring

## Status
Accepted

## Context
Zero-allocation IP/ASN enrichment using prefix tables and mmdb lookups per
AGENTS.md rule #5.

## Decision
- `scoring.PrefixTable` uses sorted CIDR entries (most-specific-first match)
  instead of external `bart` library (version unavailable); provides O(log n)
  prefix lookups with score modifiers.
- `scoring.Scorer` combines correlation results, GeoIP/ASN enrichment
  (via MMDBReader interface), and prefix scores into 0-100 risk score.
- `scoring.StubMMDB` enables testing without MaxMind data; real mmdb plugged
  in at deployment (GeoLite2 free).
- TTL from correlation: confirmed C2 336h (14d), residential VPS 12h, default
  6h.

## Consequences
- Zero-allocation hot path for IP/ASN enrichment.
- Score clamped to 0-100; risk levels low/medium/high/critical.
- MaxMind GeoLite2 free source configurable via MMDBReader.
