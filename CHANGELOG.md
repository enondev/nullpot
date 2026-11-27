# Changelog

All notable changes to nullpot are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial repo layout (go.mod, directory skeleton, CI workflow, ADR-001)
- OpenAPI 3.1 spec (Sensor Ingest + Edge Lookup API)
- OCSF-aligned ThreatEvent struct with Validate()
- STIX 2.1 Bundle/Indicator/Sighting serialization models
- MISP Core Format event/attribute export models
- XARF automated abuse report generator models (ADR-002)
- TrapModule interface (Name(), Start()) + Registry (ADR-001 contract)
- PersonaSpec YAML model + Loader for sensors/personas/*.yaml (ADR-003)
- Session-bound Canary Token generator with callback attribution (ADR-003)
- All-port TCP/UDP packet listener emitting OCSF port_scan events (ADR-004)
- SO_ORIGINAL_DST documented for Linux build tags
- Apply SO_ORIGINAL_DST syscall on Linux to recover original destination of redirected traffic
- Platform-specific build tags: widenet_linux.go (Linux), widenet_other.go (non-Linux error)
- Real OTLP HTTP exporter replacing no-op tracer stubs
- Trace context propagated across sensor→aggregator→edge API (ADR-017)
- ADR-0007: Sensor Trap Module architecture
- ADR-0017: OpenTelemetry tracing architecture
- Replace placeholder aggregator URL with proper internal endpoint in decoys/ai-compute/telemetry.js
- Re-add golangci-lint step with Go 1.26-compatible version
- Add ADR references to AGENTS.md rules 1, 5, 6, and 7
- YAML-driven decoy HTTP trap serving persona routes (ADR-005)
- Canary token injection, SHA-256 payload hashing, OCSF event emission (ADR-006)
- Safe payload handling: never execute captured content (ADR-006)
- SSH tarpit capturing auth attempts, commands, and dropped payloads
- SHA-256 quarantine (never execute), OCSF Detection Finding events (ADR-006)
- Quarantine map capped at 10,000 entries with LRU eviction
- Stateful TCP trap for Redis :6379 and Docker :2375 banners/payloads
- SHA-256 quarantine (never execute), OCSF events
- Quarantine map capped at 10,000 entries with LRU eviction
- Single-binary daemon wiring widenet + http_persona + ssh + raw_tcp modules
- Bounded buffered channel (4096) with drop-oldest overflow
- Shipper exporter (gzip JSON batch POST, batch size 100, 5s flush timeout)
- /healthz observability endpoint, graceful shutdown on SIGINT/SIGTERM (ADR-008)
- Channel closed on shutdown; health server stopped; no goroutine leaks
- POST /v1/ingest with gzip JSON decompression
- Single event or batch JSON acceptance
- ThreatEvent.Validate() before storage; 202 Accepted / 400 Bad Request
- In-memory EventStore with Add/All/Len; copy-on-read for safety
- Double-verification: recon + exploit from same IP within 24h = high confidence
- C2/IOC extractor (URLs, domains, IPs from captured commands/prompts)
- Researcher allowlist (Shodan, Censys, Shadowserver, crawlers)
- TTL decay: 6-24h scanner IPs, 7-30d confirmed C2
- ASN scoring 10x for confirmed C2 infrastructure (ADR-010)
- Sorted CIDR prefix table with most-specific-first match
- Risk scorer: correlation + GeoIP/ASN + prefix modifiers (0-100 score)
- Risk levels: low/medium/high/critical; score clamped to 0-100
- TTL: confirmed C2 336h, residential VPS 12h, default 6h
- StubMMDB for testing; real MaxMind mmdb plugged via MMDBReader (ADR-011)
- ShouldDispatch gate: no port scans, requires evidence payload
- XARF 1.0 report build with reporter/incident/evidence (no raw payloads)
- Dispatcher POSTs to configured Trust & Safety endpoints
- Dispatch record maintained in memory (ADR-012)
- KVUploader with daily write cap (default 1,000/day)
- D1Writer with daily row cap (default 100,000/day)
- Sync coordinates KV + D1 batches with error reporting
- Free-tier guardrails enforced in code (ADR-013)
- Wires ingest -> correlate -> score -> abuse -> cloudflare sync
- Allowlist check skips benign researchers
- Only critical-risk events synced to Cloudflare
- Health endpoint on :8091, graceful shutdown (ADR-014)
- Worker routes: GET /v1/ip/:ip, /v1/asn/:asn, /v1/edl/:feed.txt, /v1/stix/bundle.json, /v1/misp/manifest.json
- KV-backed <10ms reads; EDL plain-text blocklist output
- STIX 2.1 bundle with application/stix+json;version=2.1 content type
- Workers AI scheduled summarizer (score >= 75 events only)
- D1 schema: ip_reputation, asn_reputation, events, blocklist (ADR-015)
- D1 fallback for KV cache misses on GET /v1/ip/:ip and GET /v1/asn/:asn
- D1 results backfilled to KV for subsequent requests
- Parameterized SQL queries to prevent injection
- Widenet listener payload capture: SHA-256 hash and truncated PayloadPreview fields
- Widenet port binding: --widenet-listen flag defaulting to 0.0.0.0:53, replacing hardcoded 0.0.0.0:0
- Scoring ExtractedIOCs: ExtractedIOCs []string field on RiskInputs and RiskScore structs
- Ingest rate limiting: per-IP token bucket (10 req/s, burst 20)
- Ingest EventStore bounded eviction: maxEvents default 1,000,000 with FIFO eviction
- Aggregator processEvent refactor: ProcessingContext struct with helper functions
- C2 extractor wiring into processEvent pipeline
- Aggregator pipeline integration tests
- Sensor-to-aggregator integration tests via shipper

### Changed

- IsConfirmedC2 now requires high-confidence correlation AND non-empty extracted IOC evidence
- correlate.C2Extractor wired into processEvent to extract IOCs from PayloadPreview
- ADR-010 updated to document C2Extractor wiring and IsConfirmedC2 gating requirements
- Add ADR references to AGENTS.md rules 1, 5, 6, and 7

### Fixed

- Fix processEvent: only record Widenet port sweeps as recon, only record trap hits as exploitation
- Prevent single-packet scans from self-classifying as high-confidence attackers
- Fix processEvent: IsConfirmedC2 requires high-confidence correlation AND extracted IOC evidence
- Prevent score inflation from confirmed C2 bonus on recon-only events
- Replace placeholder aggregator URL with proper internal endpoint
- Widenet listener no longer discards captured payload (_ = payload replaced with SHA-256 hashing)
- Widenet sensor no longer binds to random ephemeral port 0; port validation fails fast on port 0
- processEvent no longer calls both RecordSweep and RecordHit on every event; sweeps only from Widenet, hits only from trap modules
- IsConfirmedC2 no longer always equal IsHighConfidence; now requires extracted IOC evidence

### Security

- Added per-IP rate limiting to ingest receiver to prevent gzip JSON flood exhaustion
- Added bounded FIFO eviction to EventStore to prevent unbounded memory growth
- Captured payloads are SHA-256 hashed and truncated, never executed
