# ADR-010: Double-Verification Correlation

## Status
Accepted

## Context
Double-verification correlation classifies high-confidence automated attackers
by correlating Widenet port sweeps with domain-specific trap hits from the
same IP/subnet.

## Decision
- `correlate.Engine` records sweeps and hits per IP with 24h pruning.
- High confidence requires a hit following a sweep within 24h (recon ->
  exploit escalation).
- Risk multiplier 10x for confirmed C2 infrastructure vs residential scanners.
- `correlate.C2Extractor` extracts URLs, domains, and IPs from captured
  commands/prompts (no execution).
- `correlate.Allowlist` excludes benign researchers (Shodan, Censys,
  Shadowserver, crawlers) from blocklists and XARF.
- `correlate.TTLPolicy`: 6-24h for scanner IPs, 7-30d for confirmed C2.

## Consequences
- Single-packet scans never classified as high-confidence attackers.
- Second-order infrastructure attribution scores hosting ASNs 10x higher.
- Benign researchers excluded from abuse reports and blocklists.
