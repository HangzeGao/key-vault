# ADR 0006: Fix the ordinary TC profile to SM4-HCTR without a tag

- Status: Accepted
- Date: 2026-08-11
- Supersedes: ADR 0005

## Context

The ordinary TC wire format is fixed and has only a five-byte primary header,
a six-byte security field (`SPI(2) || IV_COUNTER(4)`), a variable data field,
and a two-byte FECF. It has no authentication tag. CTR therefore allowed an
active attacker to make controlled bit changes to decrypted command fields.
The project is pre-production and has no compatibility requirement for the
provisional AES/CTR profiles.

## Decision

Ordinary TC uses one strict profile: `SM4_HCTR` (`0x0013`). Recovery Root
Prepare uses `SM4_GCM` with a 16-byte tag. No suite negotiation or AES branch
exists in the flight module.

The ordinary frame remains unchanged:

```text
primary(5) || SPI(2) || IV_COUNTER(4) || HCTR_CIPHERTEXT(N, N>=16) || FECF(2)
```

The 16-byte HCTR tweak is reconstructed on both sides as:

```text
nonce_prefix(6) || SPI(2) || IV_COUNTER(4) || 0x00000000
```

The Operational Root is 16 bytes. The SM4-CMAC counter KDF produces 32 bytes
bound to spacecraft, direction, suite, SPI, security epoch, and root version.
The first 16 bytes are the SM4 block key and the final 16 bytes are the HCTR
universal-hash key. Derived working material is never persisted.

The flight API uses caller-owned contexts and contains no mutable global state.
Calls using distinct contexts may be concurrent or nested. A single context
owns replay and rotation state and must be serialized by flight software.

The ground CCSDS module accepts a complete clear TC transfer frame and returns
a complete protected TC transfer frame. It validates the input length and FECF,
inserts the security field selected by the SA, rewrites the transfer-frame
length, and recomputes FECF. Link software transports the returned bytes without
performing a second framing step. Recovery GCM authenticates the final primary
header together with `SPI || IV_COUNTER` as its 11-byte AAD.

## Consequences

- HCTR preserves the existing frame length and removes CTR's controlled
  bit-flipping property by diffusing changes across the complete data field.
- HCTR still provides no cryptographic authenticity. FECF, replay checks, and
  plaintext validation do not replace a MAC or tag.
- The minimum ordinary data field is 16 bytes.
- Current/Next automatic promotion and authenticated SM4-GCM Root Prepare are
  retained; Previous/Grace and compatibility parsers are not introduced.
- Ground and flight must pass the same KDF, standard HCTR, complete-frame, and
  non-block-aligned interoperability vectors.
- The CCSDS module owns frame parsing and assembly; callers cannot submit a bare
  data field or assemble a protected frame from returned fragments.
