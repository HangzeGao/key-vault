# ADR 0005: Fix the TC flight profile to CTR without a tag

- Status: Accepted
- Date: 2026-08-07
- Supersedes: ADR 0004 for TC transmit wire layout only

## Context

The mission TC frame has a fixed five-byte primary header, six-byte security
field, variable data field, and two-byte FECF. The security field is fixed as a
16-bit SPI followed by a 32-bit transmitted IV counter. No authentication tag
or other cryptographic check field is present.

The previous provisional CCSDS adapter transmitted a separate sequence number,
the full suite nonce, and a suite-dependent tag. That format is incompatible
with the confirmed six-byte TC security field and contains redundant sequence
and IV values. The system has not entered production, so the provisional format
has no compatibility requirement.

## Decision

The TC transmit profile and embedded flight implementation support exactly two
fixed algorithms: `ENCRYPT_ONLY` with AES-256-CTR or SM4-CTR. CMAC and GCM remain
available to other system profiles but are rejected for ordinary TC transmit.

The TC frame is:

```text
primary(5) || SPI(2) || IV_COUNTER(4) || ciphertext(N) || FECF(2)
```

The CTR initial counter is constructed from a six-byte immutable SA nonce
prefix, SPI, IV counter, and a four-byte per-frame block counter starting at
zero. The 32-bit IV counter is allocated atomically and durably per outbound SA;
it also supplies the flight duplicate-filter sequence. No separate TC sequence
field, full transmitted nonce, tag, or configurable TC primary-header length is
retained.

The embedded C module exposes one receive interface and uses fixed memory. It
validates transfer-frame length and FECF, resolves SPI to a fixed SA/key slot,
decrypts, invokes the mission plaintext validator, persists replay state, and
only then returns plaintext. Ground and flight consume shared AES and SM4 fixed
vectors.

## Consequences

- TC provides confidentiality only. It must never be reported as authenticated,
  verified, trusted, or cryptographically replay-protected.
- FECF and command-format validation do not replace a MAC.
- An active attacker can modify ciphertext and recalculate FECF. The accepted
  threat model must state this limitation explicitly.
- A new key generation receives a new SPI and nonce prefix. IV state must not
  roll back across restart or SA rollback.
- The ordinary flight path does not contain GCM, CMAC, suite negotiation,
  dynamic policy, ground key hierarchy, databases, or general CCSDS parsing.
- Adding cryptographic integrity later requires a new explicitly versioned TC
  wire profile rather than silently interpreting existing frames differently.
