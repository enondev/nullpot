# Changelog

All notable changes to nullpot are documented in this file.

## [Unreleased]

### Phase 0 — Repository foundation & CI

- Initial repo layout (go.mod, directory skeleton, CI workflow, ADR-001)

### Phase 1 — specs/: OpenAPI 3.1 + Go serialization models

- OpenAPI 3.1 spec (Sensor Ingest + Edge Lookup API)
- OCSF-aligned ThreatEvent struct with Validate()
- STIX 2.1 Bundle/Indicator/Sighting serialization models
- MISP Core Format event/attribute export models
- XARF automated abuse report generator models (ADR-002)

### Phase 2 — sensors/internal/core: TrapModule, Persona loader, Canary Token generator

- TrapModule interface (Name(), Start()) + Registry (ADR-001 contract)
- PersonaSpec YAML model + Loader for sensors/personas/*.yaml (ADR-003)
- Session-bound Canary Token generator with callback attribution (ADR-003)

### Phase 3 — sensors/internal/widenet: SO_ORIGINAL_DST listener

- All-port TCP/UDP packet listener emitting OCSF port_scan events (ADR-004)
- SO_ORIGINAL_DST documented for Linux build tags

### Phase 4 — sensors/internal/traps/http_persona: YAML-driven HTTP/HTTPS trap

- OpenAPI/YAML-driven decoy HTTP trap serving persona routes (ADR-005)
- Canary token injection, SHA-256 payload hashing, OCSF event emission (ADR-006)
- Safe payload handling: never execute captured content (ADR-006)

### Phase 5 — sensors/internal/traps/ssh: SSH tarpit & command/dropper trap

- SSH tarpit capturing auth attempts, commands, and dropped payloads
- SHA-256 quarantine (never execute), OCSF Detection Finding events (ADR-006)
- Quarantine map capped at 10,000 entries with LRU eviction

### Phase 6 — sensors/internal/traps/raw_tcp: stateful banner/payload traps

- Stateful TCP trap for Redis :6379 and Docker :2375 banners/payloads
- SHA-256 quarantine (never execute), OCSF events
- Quarantine map capped at 10,000 entries with LRU eviction

### Phase 7 — sensors/cmd/sensor: unified sensor daemon

- Single-binary daemon wiring widenet + http_persona + ssh + raw_tcp modules
- Bounded buffered channel (4096) with drop-oldest overflow
- Shipper exporter (gzip JSON batch POST, batch size 100, 5s flush timeout)
- /healthz observability endpoint, graceful shutdown on SIGINT/SIGTERM (ADR-008)
- Channel closed on shutdown; health server stopped; no goroutine leaks

### Phase 8 — aggregator/internal/ingest: OpenAPI webhook receiver

- POST /v1/ingest with gzip JSON decompression
- Single event or batch JSON acceptance
- ThreatEvent.Validate() before storage; 202 Accepted / 400 Bad Request
- In-memory EventStore with Add/All/Len; copy-on-read for safety

### Phase 9 — aggregator/internal/correlate: double-verification engine

- Double-verification: recon + exploit from same IP within 24h = high confidence
- C2/IOC extractor (URLs, domains, IPs from captured commands/prompts)
- Researcher allowlist (Shodan, Censys, Shadowserver, crawlers)
- TTL decay: 6-24h scanner IPs, 7-30d confirmed C2
- ASN scoring 10x for confirmed C2 infrastructure (ADR-010)

### Phase 10 — aggregator/internal/scoring: prefix table + risk scorer

- Sorted CIDR prefix table with most-specific-first match
- Risk scorer: correlation + GeoIP/ASN + prefix modifiers (0-100 score)
- Risk levels: low/medium/high/critical; score clamped to 0-100
- TTL: confirmed C2 336h, residential VPS 12h, default 6h
- StubMMDB for testing; real MaxMind mmdb plugged via MMDBReader (ADR-011)

### Phase 11 — aggregator/internal/abuse: XARF report dispatcher

- ShouldDispatch gate: no port scans, requires evidence payload
- XARF 1.0 report build with reporter/incident/evidence (no raw payloads)
- Dispatcher POSTs to configured Trust & Safety endpoints
- Dispatch record maintained in memory (ADR-012)

### Phase 12 — aggregator/internal/cloudflare: batched KV + D1 writer

- KVUploader with daily write cap (default 1,000/day)
- D1Writer with daily row cap (default 100,000/day)
- Sync coordinates KV + D1 batches with error reporting
- Free-tier guardrails enforced in code (ADR-013)

### Phase 13 — aggregator/cmd/aggregator: central daemon

- Wires ingest -> correlate -> score -> abuse -> cloudflare sync
- Allowlist check skips benign researchers
- Only critical-risk events synced to Cloudflare
- Health endpoint on :8091, graceful shutdown (ADR-014)

### Phase 14 — edge-api/: Cloudflare Worker + KV + D1

- Worker routes: GET /v1/ip/:ip, /v1/asn/:asn, /v1/edl/:feed.txt,
  /v1/stix/bundle.json, /v1/misp/manifest.json
- KV-backed <10ms reads; EDL plain-text blocklist output
- STIX 2.1 bundle with application/stix+json;version=2.1 content type
- Workers AI scheduled summarizer (score >= 75 events only)
- D1 schema: ip_reputation, asn_reputation, events, blocklist (ADR-015)
