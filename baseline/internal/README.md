# Backend Internal Modules

This directory contains the backend implementation for the KVLT engineering baseline.
Packages under `internal/` are intentionally not public API. Keep dependencies explicit,
preserve plane isolation, and prefer small interfaces owned by the consuming package.

## Architecture Boundaries

The backend is organized around four logical planes:

| Plane | Backend responsibility | Must not do |
| --- | --- | --- |
| Management Plane | Key metadata, lifecycle operations, tenant envelope config, policy reload/read, audit/lifecycle views. | Execute encrypt/decrypt hot path or return plaintext key material. |
| Data Plane | Encrypt, decrypt, batch crypto, envelope encode/decode, AAD validation, nonce use. | Mutate key lifecycle, tenant config, policy, or audit state. |
| Key Plane | CRK unseal, DEK wrap/unwrap, TPM/vTPM interaction, short TTL DEK lease. | Expose browser/public APIs or perform business authorization decisions. |
| Audit Plane | Audit events, hash chains, verification, outbox forwarding. | Record secrets, tokens, plaintext, CRK/DEK material, or silently ignore audit failure on high-risk operations. |

API authorization is enforced in `api/middleware.APIAccess` before handlers run.
Handler-level checks are still used as defense in depth.

## Dependency Direction

Use this direction unless there is a strong reason not to:

```text
cmd/key-vault
  -> bootstrap
    -> api
    -> application
    -> lifecycle / audit / auditchain / outbox / policysig
    -> repository
    -> resolver/keyresolver
    -> tpm/provider
    -> crypto
    -> domain
```

Lower-level packages must not import HTTP handlers or bootstrap wiring. Application services
should depend on narrow local interfaces instead of concrete repository implementations.

## Module Map

| Module | Purpose | Key packages/files | Notes |
| --- | --- | --- | --- |
| `api` | HTTP boundary for UI/API routes and request middleware. | `admin`, `crypto`, `tenant`, `baselineapi`, `middleware`, `server` | Owns route registration, auth extraction, body parsing, and API error responses. Do not put business rules here unless they are request-shape or authorization checks. |
| `application` | Use-case layer for key and crypto operations. | `keys`, `crypto` | Owns orchestration, audit calls, policy checks, key expiry checks, and envelope config application. Does not own storage implementation. |
| `audit` | Structured audit event recording and WAL integration. | `audit.go`, `redaction` | Sensitive identifiers must be hashed/redacted. High-risk management operations should fail closed when audit fails. |
| `auditchain` | Append-only audit hash chain and verification service. | `service.go` | Used by audit UI/API to list, verify, and inspect chain heads. |
| `auth` | Caller identity and authentication helpers. | `principal`, `jwt`, `hmacsign` | `principal.Principal` carries plane, scopes, roles, tenant, and auth method. Plane access is strict unless a development static token explicitly lists multiple planes. |
| `bootstrap` | Composition root for the service. | `bootstrap.go` | Creates repository, TPM provider, resolver, policies, services, handlers, lifecycle worker, and static tokens. Avoid business logic here. |
| `config` | Runtime configuration and environment overrides. | `config.go` | Defaults must be safe for local baseline. Validate clamps invalid lifecycle/server/nonce settings. |
| `crypto` | Cryptographic primitives and envelope format support. | `aead`, `aad`, `envelope`, `nonce` | Keep parsing strict and deterministic. Never log raw keys, plaintext, nonce lease internals beyond safe identifiers. |
| `domain` | Pure domain rules and state machines. | `key/state`, `policy` | Should stay independent from HTTP, repository, and bootstrap. |
| `errorsx` | Structured domain/API error type and HTTP status mapping. | `errors.go` | Prefer typed error codes over ad hoc string errors across service/API boundaries. |
| `lifecycle` | Async lifecycle worker and transactional outbox processing. | `worker.go` | Handles expiry scans, destroy jobs, cache invalidation, and audit forwarding. Expired keys emit `key.expired`; keys within warning window emit `key.expiry_approaching`. |
| `logging` | Structured logger with mandatory redaction. | `logging.go` | Add sensitive field names here before logging any new security-relevant metadata. |
| `outbox` | Transactional outbox service wrapper. | `service.go` | Repository-backed interface for creating/listing events. Worker owns delivery behavior. |
| `policysig` | Signed policy package generation, verification, and reload. | `manager.go` | Policy reload is a management-plane operation and must be audited. |
| `repository` | Storage boundary and implementations. | `repository.go`, `models`, `memory`, `postgres` | Interface lives at the boundary. Implementations must preserve tenant scoping and optimistic/idempotent semantics. |
| `resolver` | Key resolver and DEK lease handling. | `keyresolver` | This is the main internal key-plane boundary. Data plane services must use it rather than directly touching TPM/CRK material. |
| `tpm` | TPM/vTPM provider abstraction. | `provider` | Hardware and software providers must expose the same seal/unseal contract. Software provider is for local baseline only. |
| `web` | Embedded frontend assets. | `embed.go`, `dist` | `dist` is generated by the frontend build and embedded into the Go binary. |

## API Modules

`api/server` wires middleware and route handlers. The auth chain is:

```text
RequestID -> BodyLimit -> ReadBody -> Auth -> APIAccess -> handler
```

`APIAccess` is the central externally visible route matrix. When adding an API route:

1. Register the route in the owning handler package.
2. Add the route to `accessRuleFor`.
3. Add or update unit tests in `api/middleware`.
4. Keep local handler scope checks for high-risk mutations.

## Application Modules

`application/keys` owns key lifecycle use cases:

- create/import key metadata and initial wrapped material
- update metadata and `expires_at`
- enable/disable, prepare and activate imported versions, schedule/cancel destroy
- derive external status such as `EXPIRED`
- provide lifecycle expiry candidates

`application/crypto` owns crypto use cases:

- encrypt/decrypt and batch equivalents
- policy and key status checks
- key resolver interaction for DEK lease/unwrap
- envelope format selection and tenant envelope config application

Application packages should not import HTTP packages. They should return typed errors from
`errorsx` when the API needs stable error codes.

## Storage Modules

`repository.Repository` is the contract consumed by services. `memory` is the fast local/test
implementation. `postgres` is the durable implementation and owns migrations.

Repository implementations must:

- preserve tenant isolation on key and tenant-scoped reads
- avoid returning plaintext key material
- keep wrapped material and metadata distinct
- support idempotency records for mutating APIs
- implement lifecycle/outbox claim semantics consistently

## Crypto And Key Plane Modules

`crypto/aad` provides deterministic AAD encoding. `crypto/envelope` provides binary and JSON
encodings of the same normalized envelope profile. `crypto/nonce` provides nonce lease management.
`resolver/keyresolver` is the controlled path to unwrap/lease DEKs.

Rules:

- Data plane code must not call TPM providers directly.
- Do not add plaintext DEK/CRK fields to DTOs, audit payloads, logs, or API responses.
- Envelope custom fields are transport/profile metadata only; they must not weaken AAD or policy checks.

## Lifecycle Modules

The lifecycle worker periodically creates `key_expiry_check` jobs and processes pending jobs/outbox
events. Expiry behavior is split by time:

- `expires_at <= now`: emit `key.expired`
- `now < expires_at <= now + expiry_warning_window`: emit `key.expiry_approaching`
- outside the warning window: no lifecycle event

The warning window defaults to `7d` and can be overridden with
`KVLT_LIFECYCLE_EXPIRY_WARNING_WINDOW`.

## Testing

Preferred unit-test commands:

```powershell
cd baseline
$env:GOCACHE='C:\Users\gaoha\Documents\key-vault\.gocache'
go test ./internal/...
```

Focused packages:

```powershell
go test ./internal/api/middleware ./internal/bootstrap ./internal/lifecycle ./internal/application/keys
go test ./internal/application/crypto ./internal/crypto/...
go test ./internal/repository/memory ./internal/domain/key/state
```

End-to-end tests under `test/e2e` are intentionally separate and slower. Do not require them for
small internal package changes unless the change crosses API, storage, and frontend behavior.

## Adding A New Internal Module

Before adding a package:

1. Confirm the responsibility does not fit an existing module.
2. Define its plane and dependency direction.
3. Keep exported types minimal.
4. Add package-level tests for boundary behavior.
5. Update this README if the module is a new top-level directory or changes a plane contract.
