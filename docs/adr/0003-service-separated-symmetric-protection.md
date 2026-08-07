# ADR 0003: Bind security services to fixed algorithm families

- Status: Accepted
- Date: 2026-07-29

## Context

The original crypto seam exposed every block-cipher mode as an `AEAD`, including
modes that did not authenticate. That abstraction could not represent an
authentication-only operation and made it possible for callers to assume
security properties a suite did not provide.

The system needs confidentiality-only CTR, authentication-only CMAC, and
authenticated-encryption GCM at the same time. The project has not shipped, so
the obsolete ECB model and wire identifiers do not need compatibility support.

## Decision

Model the security service type explicitly and make the mapping closed:

- `AUTH_ONLY` → CMAC (`AES_256_CMAC`, `SM4_CMAC`);
- `ENCRYPT_ONLY` → CTR (`AES_256_CTR`, `SM4_CTR`);
- `AUTH_ENCRYPT` → GCM (`AES_256_GCM`, `SM4_GCM`).

The `crypto/suite` module owns suite identifiers, service types, supported
operations, key purpose, nonce size, and tag size. Policy, crypto primitives,
application workflows, and presentation adapters consume this interface rather
than duplicating mappings or inferring behavior from suite-name suffixes.

Encryption suites use the envelope and `encrypt`/`decrypt` operations. CMAC uses
a detached, versioned authenticator and separate `authenticate`/`verify`
operations. CMAC cannot be constructed through the encryption interface.

Keys are bound to one immutable purpose:

- `encrypt_decrypt` for CTR or GCM;
- `authenticate_verify` for CMAC;
- `key_wrap` for the existing authenticated key-transfer boundary.

Policy validation checks the exact algorithm, key size, mode, service type, nonce
strategy, MAC, and composition for every suite. Active suites may create new
protected data. Active and deprecated suites may consume historical data.

GCM and CTR share the durable uniqueness lease. GCM uses the leased 96-bit
value directly; CTR appends a zero 32-bit block counter to create its 128-bit
initial counter. CMAC uses a full 128-bit tag and authenticates a canonical
domain prefix plus suite, tenant, key, key version, policy version, message
length, and message. Verification compares tags in constant time.

## Consequences

- Callers must choose the required security property rather than a generic
  "crypto mode."
- `service_type` is derived from `suite_id`; accepting both as independent
  configuration would create invalid combinations and is forbidden.
- CTR rejects AAD and offers no modification detection. Applications requiring
  both properties must use GCM.
- CMAC returns the message unchanged and its detached tag is not an envelope.
- Separate authorization scopes (`crypto:authenticate`, `crypto:verify`) allow
  authentication rights to be granted independently from encryption rights.
- ECB suite IDs and behavior are removed. No migration path is provided because
  the system has not entered production.
