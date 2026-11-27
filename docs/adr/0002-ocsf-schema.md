# ADR-002: OCSF Schema

## Status
Accepted

## Context
All sensor modules emit standardized OCSF-mapped JSON payloads. AGENTS.md
specifies a `class_uid: 2004`, `category_uid: 2`, `activity_id: 1`
`ThreatEvent` with `metadata`, `src_endpoint`, `dst_endpoint`,
`finding_info`, and `enrichment` sub-structs.

## Decision
Adopt OCSF-aligned `ThreatEvent` struct in `specs/ocsf.go`:
- `metadata.product` identifies the emitting sensor (name, uid, region).
- `src_endpoint` / `dst_endpoint` capture IP + port.
- `finding_info` captures uid, title, and exploit types.
- `enrichment` captures module, persona_id, fingerprint, canary_id,
  payload_preview, payload_sha256, and extracted_iocs.

Payloads are hashed (SHA-256) and never executed. `Validate()` enforces
required fields before emission to the aggregator.

## Consequences
- Zero-mapping ingestion into Amazon Security Lake, Splunk, and Elastic.
- Consistent event schema across widenet, http_persona, ssh, raw_tcp traps.
- Enrichment fields enable canary callback attribution and C2/IOC extraction.
