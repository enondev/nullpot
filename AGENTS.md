# AGENTS.md

## Project Overview
A clean-slate, modular, globally distributed Threat & Abuse Intelligence Platform combining Widenet port reconnaissance traps, high-interaction AI/Compute/Cloud protocol honeypots, and curated OSINT/BGP feeds.
- **Primary Value Proposition:** Zero-false-positive, evidence-backed IP/ASN reputation, STIX 2.1 / MISP threat feeds, automated XARF abuse reporting, and dynamic firewall blocklists (EDLs) driven by "double-verification" correlation (Widenet Recon + Domain-Specific Exploitation + Second-Order C2/Dropper Infrastructure Attribution + Canary Token Tracking).
- **Target Buyers:** Mid-market SOCs/MSSPs, AI/GPU/Cloud hosting providers (preventing free-tier abuse & scraping), Fintech/SaaS fraud teams, and Enterprise Firewall/SIEM admins.
- **Architecture:** Modular Go Edge Sensors -> Central Go Correlation & Risk Scoring Engine -> Cloudflare Edge (KV, D1, Workers AI).

## Tech Stack & Standards
- **Sensors & Aggregator:** Go (`net`, `syscall`/`SO_ORIGINAL_DST`, `golang.org/x/crypto/ssh`, `://github.com` for IP prefix radix trees, `://github.com` for GeoIP/ASN, `gopkg.in/yaml.v3`).
- **Edge Compute & Storage:** Cloudflare Workers (TypeScript), Cloudflare KV, Cloudflare D1 (SQLite), Cloudflare Workers AI.
- **Industry Specifications & Protocols:**
  - **OpenAPI 3.1 (`specs/openapi.yaml`):** Governs Sensor-to-Aggregator ingestion endpoints (gzip JSON), Customer Edge API contracts, and authentic HTTP/AI/Cloud honeypot persona mocking (e.g., OpenAI, Ollama, Docker Engine APIs).
  - **OCSF (`Open Cybersecurity Schema Framework`):** Canonical internal schema for all sensor telemetry (`Network Activity` / `Detection Finding`), enabling zero-mapping ingestion into Amazon Security Lake, Splunk, and Elastic.
  - **STIX 2.1 (`application/stix+json;version=2.1`):** Served as cached static JSON bundles (`GET /v1/stix/bundle.json`) for SIEM/SOAR integration alongside plain-text firewall External Dynamic Lists (EDLs).
  - **MISP Core Format (`GET /v1/misp/manifest.json`):** Standardized JSON feed export for CERTs, ISACs, and threat-intelligence sharing communities.
  - **XARF (`eXtended Abuse Reporting Format`):** Machine-readable JSON abuse reports generated automatically by the aggregator to notify hosting/cloud Trust & Safety teams (AWS, Hetzner, DigitalOcean, Cloudflare) of active compromised infrastructure.
  - **Declarative Persona Specs (`sensors/personas/*.yaml`):** YAML manifests defining decoy software banners, HTTP routes, response schemas, IOC capture rules, and canary token injection without recompiling Go binaries.
- **Cloudflare Free-Tier Guardrails (Strict):**
  - Never stream raw scanner or BGP firehose traffic directly to Cloudflare.
  - Perform stateful sliding-window aggregation, deduplication, and scoring in-memory inside the Central Go Aggregator first.
  - Batch KV writes (stay well under 1,000 writes/day) and batch D1 SQL inserts (stay well under 100,000 row writes/day).
  - Invoke Workers AI only on confirmed high-severity multi-stage attacks or novel exploit payloads.

## Repository Structure
```text
/
├── specs/
│   ├── openapi.yaml         # OpenAPI 3.1 spec for Sensor Ingest API & Customer Edge API
│   ├── ocsf.go              # OCSF-aligned ThreatEvent normalization structs
│   ├── stix21.go            # STIX 2.1 Bundle/Indicator/Sighting serialization models
│   ├── misp.go              # MISP Core Format event/attribute export models
│   └── xarf.go              # XARF automated abuse report generator models
├── sensors/
│   ├── cmd/sensor/          # Unified single-binary sensor daemon
│   ├── personas/            # Declarative YAML persona specs (ollama.yaml, openai.yaml, docker.yaml, env-leak.yaml)
│   └── internal/
│       ├── core/            # TrapModule interface, Persona loader, & Canary Token generator
│       ├── widenet/         # All-port TCP/UDP listener using Linux SO_ORIGINAL_DST
│       ├── traps/
│       │   ├── http_persona/# OpenAPI/YAML-driven HTTP/HTTPS trap (Ollama, OpenAI, CVE, Canary)
│       │   ├── ssh/         # Modular Go SSH tarpit & command/dropper trap
│       │   └── raw_tcp/     # Stateful banner/payload traps (Redis :6379, Docker :2375)
│       └── shipper/         # Non-blocking buffered channel HTTP/batch exporter (OpenAPI gzip client)
├── aggregator/
│   ├── cmd/aggregator/      # Central ingestion, correlation, and CF sync daemon
│   └── internal/
│       ├── ingest/          # OpenAPI sensor webhook receiver, Canary callback listener, & OSINT/BGP pullers
│       ├── correlate/       # Double-verification engine, C2/URL extractor, & researcher allowlist
│       ├── scoring/         # In-memory bart radix tree + MaxMind GeoIP/ASN risk scorer
│       ├── abuse/           # Automated XARF report dispatcher for confirmed compromised hosts
│       └── cloudflare/      # Batched KV snapshot uploader (API, EDLs, STIX, MISP) & D1 event writer
├── decoys/
│   └── ai-compute/         # Static decoy site (landing, login, signup, dashboard, API, pricing, products, topology, console, contact, 404)
│       ├── telemetry.js    # Obfuscated telemetry collector (clicks, mouse, scroll, keyboard, visibility, canvas/WebGL/audio/font fingerprints)
│       ├── canary tokens   # Session-bound fake credentials/URLs in decoy responses
│       └── netlify.toml, vercel.json, _headers, _redirects  # Static host configs
├── edge-api/               # Cloudflare Worker (TypeScript) + KV + D1 + Workers AI
│   ├── package.json        # wrangler + typescript dependencies
│   ├── tsconfig.json       # strict ES2022, Bundler resolution
│   ├── wrangler.toml       # KV, D1, AI bindings
│   ├── src/
│   │   ├── routes/         # GET /v1/ip/:ip, GET /v1/asn/:asn, GET /v1/edl/:feed.txt, GET /v1/stix/bundle.json, GET /v1/misp/manifest.json
│   │   └── ai/             # Scheduled Workers AI threat-campaign summarizer (score >= 75 only)
│   └── migrations/         # Cloudflare D1 SQLite schema
├── .github/workflows/      # CI/CD (gofmt, go vet, go test, golangci-lint, TS typecheck, Pages + wrangler deploy)
├── DEPLOY.md               # Full deployment guide
└── CHANGELOG.md            # Per-phase changelog
```

## Core Architecture & Engineering Rules
1. **Modular Plugin Interface (`TrapModule`) + Persona Specs:**
   - Every protocol engine must implement `TrapModule` (`Name() string`, `Start(ctx context.Context, events chan<- ocsf.ThreatEvent) error`).
   - HTTP/AI/Cloud decoys must load behavior, headers, routes, and fake schemas from declarative YAML Persona files (`sensors/personas/*.yaml`) or OpenAPI specs so decoys can be rotated without recompilation.
2. **Non-Blocking Sensor Hot Path:**
   - Protocol listeners must never block on network I/O to the central aggregator. Push all telemetry to a bounded, buffered Go channel (`chan ocsf.ThreatEvent`) with drop-oldest overflow protection so attackers cannot stall or fingerprint sensors.
3. **Canary Token Injection & Callback Attribution:**
   - Persona specs with `canary_token_inject: true` embed unique, session-bound fake credentials/URLs in decoy responses.
   - Any downstream callback or reuse of a canary token links the original reconnaissance session to secondary attacker infrastructure across VPNs/ASNs.
4. **Double-Verification Correlation & Scoring:**
   - **Recon + Exploit Escalation:** Correlate Widenet port sweeps with subsequent domain-specific trap hits from the same IP/subnet to classify high-confidence automated attackers.
   - **Second-Order Infrastructure Attribution:** Extract outbound payload URLs, C2 domains/IPs, and callback targets from captured commands/prompts; resolve and score those hosting ASNs 10x higher than disposable residential scanner IPs.
   - **Benign Researcher Allowlisting:** Verify reverse-DNS/ASN ownership for known benign scanners (Shodan, Censys, Shadowserver, major search crawlers) and exclude them from blocklists and XARF reports.
   - **Aggressive TTL Decay:** Assign short TTLs (6–24h) to compromised residential/VPS scanner IPs and long TTLs (7–30d) to confirmed C2/malware staging infrastructure.
5. **Zero-Allocation Hot Paths in Aggregator:** Use `gaissmai/bart` prefix tables and memory-mapped `.mmdb` lookups for all IP/ASN enrichment.
6. **Safe Payload Handling & Legal Guardrails:**
   - Never execute captured binaries or scripts; hash (`SHA-256`), extract static IOCs, and quarantine safely.
   - Do not market honeypot endpoints to legitimate human users; expose unadvertised protocol listeners designed strictly to catch automated scanning and exploitation.
   - Only dispatch XARF abuse reports for high-confidence, evidence-backed exploitation/malware drops (never for single-packet port scans).

7. **Static Decoy Site (`decoys/ai-compute/`):**
   - YAML-driven HTTP/HTTPS decoy personas (landing, login, signup, dashboard, API, pricing, products, topology, console, contact)
   - telemetry.js: obfuscated aggregator callback URL (base64 + concatenation), prefixed token IDs
   - Fingerprinting: canvas, WebGL renderer/vendor, AudioContext, fonts, connection (effectiveType/downlink/rtt), deviceMemory
   - Interaction tracking: all clicks (tag/href/text), sampled mouse movement (x/y), max scroll depth, sampled keyboard count, visibility/tab changes
   - Batched beaconing: navigator.sendBeacon, 10 events or 3s flush, to POST /v1/telemetry/callback
   - Chaotic jitter (random micro-movements), randomly-disabled buttons to disrupt automated clicking
   - Recursive topology pages (topology.html) and iframe recursion trap automated crawlers
   - Fake OAuth buttons: some redirect to topology trap (infinite recursion), others silently POST then show "temporarily unavailable" error
   - Fake login/signup forms capture credentials and POST to aggregator before simulating error/success
   - D1-backed contact form submits to external Workers endpoint
   - Honeypot links (/admin, /.env, /phpmyadmin, etc.) disallowed in robots.txt but present in page source

8. **CI/CD (`.github/workflows/ci.yml`):**
   - Go: gofmt, go vet, go test, golangci-lint on push/PR to main
   - TypeScript: npm install, npm run typecheck for edge-api
   - Deploy: Cloudflare Pages (decoy site) + wrangler deploy (edge-api Worker) on push to main
   - Required secrets: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CF_WEB_ANALYTICS_TOKEN

## Unified Event Schema (`ocsf.ThreatEvent` - OCSF & OpenAPI 3.1 Aligned)
All sensor modules must emit standardized OCSF-mapped JSON payloads:
```json
{
  "class_uid": 2004,
  "category_uid": 2,
  "activity_id": 1,
  "time": "2026-11-26T23:26:00Z",
  "metadata": {
    "version": "1.3.0",
    "product": {
      "name": "EdgeTrapSensor",
      "uid": "edge-eu-fra-01",
      "region": "eu-central"
    }
  },
  "src_endpoint": {
    "ip": "203.0.113.45",
    "port": 54321
  },
  "dst_endpoint": {
    "port": 11434
  },
  "finding_info": {
    "uid": "evt_01jf9x8z7y6w5v4u3t2s1r",
    "title": "LLM Inference Prompt Injection & Dropper Attempt",
    "types": ["exploit_attempt"]
  },
  "enrichment": {
    "module": "http_persona",
    "persona_id": "llm-ollama-v0.5",
    "fingerprint": "ja4_or_client_banner",
    "canary_id": "cnry_9f8a7b6c5d4e",
    "payload_preview": "POST /api/generate ...",
    "payload_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "extracted_iocs": ["http://198.51.100"]
  }
}
```

## Current MVP Build Priorities
1. **`specs/`:** Define `openapi.yaml` (Sensor Ingest + Edge Lookup API) and Go serialization models (`ocsf.go`, `stix21.go`, `misp.go`, `xarf.go`).
2. **`sensors/`:** Implement the unified Go sensor daemon with `TrapModule`, YAML Persona loader (with Canary Token injection), `SO_ORIGINAL_DST` Widenet listener, and Fake Ollama/OpenAI HTTP persona.
3. **`aggregator/`:** Implement the OpenAPI webhook receiver, double-verification correlation engine, C2/IOC extractor, MaxMind GeoIP/ASN enrichment, XARF reporter, and batched Cloudflare KV uploader.
4. **`edge-api/`:** Deploy the Cloudflare Worker + KV + D1 schema serving `<10ms` `GET /v1/ip/:ip`, `GET /v1/asn/:asn`, `GET /v1/stix/bundle.json`, `GET /v1/misp/manifest.json`, and firewall-ready `GET /v1/edl/blocklist.txt`.