# ADR-005: HTTP Persona Trap

## Status
Accepted

## Context
HTTP/AI/Cloud decoys must load behavior, headers, routes, and fake schemas
from declarative YAML Persona files so decoys can be rotated without
recompilation. The http_persona trap serves these routes and captures
requests/payloads.

## Decision
- `http_persona.TrapModule` implements `core.TrapModule`.
- On Start, registers every route from every loaded persona spec against an
  `http.ServeMux`, serving the decoy response (status, body, headers) defined
  in the spec.
- On each request: injects canary tokens (if `canary_token_inject: true`),
  captures the request body, computes SHA-256, emits an OCSF event with
  `module=http_persona`, `persona_id`, `fingerprint` (User-Agent),
  `payload_preview`, `payload_sha256`, and `canary_id`.
- Captured payloads are hashed and never executed (safe payload handling,
  ADR-006).

## Consequences
- Decoy routes rotate by editing YAML, no recompilation.
- Canary token reuse links reconnaissance sessions to secondary
  infrastructure.
