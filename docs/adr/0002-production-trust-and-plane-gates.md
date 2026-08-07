# ADR 0002: Production trust and public-plane gates

- Status: Accepted
- Date: 2026-07-28
- Cryptographic-suite portion: Superseded by ADR 0003

## Context

The baseline previously allowed one HTTP process to expose management, data,
and ops routes; generated a policy signing key at every startup; accepted
development authentication in production-shaped deployments; and persisted a
browser bearer token. Those choices made local demonstrations easy but left
security boundaries implicit and restart behavior unstable.

## Decision

Production startup is fail-closed and requires durable external trust:

- one public plane per process;
- TLS 1.3 with mandatory client-certificate verification;
- asymmetric JWT verification through an HTTPS cached JWKS adapter;
- persistent Ed25519 policy trust anchors and a signed policy package;
- a deployment-specific audit-redaction pepper;
- PostgreSQL, native TPM, audit WAL, PITR, and restore-drill evidence.

Development-only HMAC/static tokens and generated policy keys remain available
only outside production. Browser credentials remain in process memory.
Cryptographic policy validation is fail-closed and every operation requires an
explicit Key. The service-separated suite model is defined by ADR 0003.

## Consequences

Configuration errors and unavailable trust dependencies stop startup. Each
public plane has a smaller route and scheduler surface. Operators must provision
certificates, identity metadata, signed policy, TPM context, and recovery
evidence before deployment.

This decision does not claim physical Key Plane isolation. A separate Key Plane
RPC, node enrollment/envelope distribution, and transactional CRK rotation
remain explicit release blockers in `baseline/docs/PRODUCTION_SECURITY.md`.
