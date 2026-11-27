# ADR-006: Safe Payload Handling

## Status
Accepted

## Context
Captured binaries/scripts/droppers must never be executed. Legal guardrails
require hashing (SHA-256), static IOC extraction, and safe quarantine.

## Decision
- All trap modules compute `payload_sha256` on captured content and never
  pass it to an interpreter/executor.
- SSH and raw_tcp traps quarantine captured payloads by hash only.
- XARF reports (Phase 11) reference `payload_sha256` and `extracted_iocs`
  but never the raw payload.

## Consequences
- Eliminates accidental malware execution on the sensor host.
- Enables evidence-backed abuse reporting without live-sample handling.
