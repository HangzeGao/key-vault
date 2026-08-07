# ADR 0004: Layer CCSDS over a protocol-neutral raw protection core

- Status: Accepted
- Date: 2026-08-06

## Context

The system currently needs one link-security protocol: TC frame protection and
AOS frame unprotection for a CCSDS mission profile. The existing public crypto
application service produces Key Vault Envelopes and canonical CMAC metadata;
those formats must not appear on a CCSDS wire. Conversely, CCSDS frame parsing,
SPI lookup, sequence state, replay handling, and authenticated-byte construction
must not leak into generic cryptographic primitives.

The project has not entered production, so an intermediate compatibility layer
or preservation of obsolete wire behavior would add risk without value. There
is also no second protocol whose requirements justify a plugin framework or a
generic protocol description language.

## Decision

Introduce a protocol-neutral internal raw-protection service with a small
request/result contract. It owns key and historical policy resolution, leased
nonce allocation, size limits, and the closed service mapping established by
ADR 0003:

- `AUTH_ONLY` uses CMAC;
- `ENCRYPT_ONLY` uses CTR;
- `AUTH_ENCRYPT` uses GCM.

The CCSDS module is the sole owner of transfer-frame layout and Managed
Parameters. It resolves a Security Association, constructs the exact security
header and authenticated bytes after nonce allocation, and assembles or parses
the frame. TC IV-counter allocation and AOS replay state are durable and
transactional. Replay state advances only after successful authentication.

Protocol-scoped keys are bound to one exact Security Association key version and
cannot be used through the generic crypto API. The generic protection core does
not import CCSDS. The CCSDS module depends on narrow interfaces for raw
protection and association state; PostgreSQL implements the durable production
adapter while an in-memory adapter supports deterministic tests.

Do not add a protocol registry, plugin lifecycle, or generic frame schema until
a second concrete protocol creates demonstrated variation. The current seam is
the narrow raw-protection contract, which is sufficient to add another adapter
later without pre-designing its wire model.

## Consequences

- CCSDS wire data never contains a Key Vault Envelope or generic CMAC metadata.
- Frame authentication covers bytes selected by the CCSDS adapter, while key,
  policy, nonce, and primitive rules remain centralized.
- Security Association provisioning must select protocol-scoped key material,
  an exact key version, and a matching suite.
- Sequence and replay state survive process restart; an eight-byte sequence
  space is represented without signed-integer truncation.
- Mission profiles must explicitly configure primary-header lengths and Managed
  Parameters. Unsupported CCSDS profile options are rejected rather than
  guessed.
- A future protocol may implement a sibling adapter over the raw-protection
  contract. A registry is reconsidered only when multiple adapters need common
  runtime discovery or selection.
