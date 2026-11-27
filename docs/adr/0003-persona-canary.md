# ADR-003: Persona Specs & Canary Tokens

## Status
Accepted

## Context
HTTP/AI/Cloud decoys must load behavior, headers, routes, and fake schemas
from declarative YAML Persona files (`sensors/personas/*.yaml`) so decoys can
be rotated without recompilation. Persona specs with `canary_token_inject:
true` embed unique, session-bound fake credentials/URLs in decoy responses.

## Decision
- PersonaSpec model in `sensors/internal/core/persona.go`: id, name, banner,
  canary_token_inject, routes (path/method/response/capture), ioc_capture.
- Loader reads `sensors/personas/*.yaml`, validates required fields (id,
  banner, at least one route), defaults method to GET.
- CanaryToken generator in `sensors/internal/core/canary.go`: random hex
  token, `cnry_` prefixed id, bound to a session id, kind (credential/url),
  created_at, value. Thread-safe registry maps token->CanaryToken and
  session->tokens for callback attribution.

## Consequences
- Decoys rotate without recompiling Go binaries.
- Canary token reuse links reconnaissance sessions to secondary attacker
  infrastructure across VPNs/ASNs.
- Token uniqueness prevents forgery/replay attribution.
