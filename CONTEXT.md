# Key Vault

This context governs cryptographic keys, the policies that authorize their use, and the envelopes that preserve the decision context of each operation.

## Policy Governance

**Crypto Policy**:
A versioned set of cryptographic suites and usage rules that governs key and data operations.
_Avoid_: Algorithm config, cipher settings

**Signed Policy Package**:
An integrity-protected publication of a Crypto Policy that becomes trusted only after signature and semantic validation.
_Avoid_: Policy file, policy JSON

**Current Policy Version**:
The activated version of a Crypto Policy used for new decisions such as key creation and encryption.
_Avoid_: Latest policy

**Historical Policy Version**:
An earlier trusted version retained so a version-bound operation can be evaluated under the rules recorded when it was created.
_Avoid_: Old config, stale policy

**Policy Trust Anchor**:
A trusted public signing identity authorized to validate Signed Policy Packages.
_Avoid_: Policy secret, signing password

## Cryptographic Material

**Envelope**:
A versioned ciphertext container that records the key, key version, suite, and Crypto Policy version required to interpret a protected payload.
_Avoid_: Ciphertext blob, encrypted JSON

**Caller AAD**:
Opaque bytes supplied by a caller and authenticated by an AAD-capable suite without being interpreted or canonicalized by the Key Vault.
_Avoid_: Envelope metadata, server AAD

**Key Version**:
An immutable generation of cryptographic material belonging to a Key.
_Avoid_: Key copy, rotated key

## Link Security

**Security Association**:
A direction-specific CCSDS binding from an SPI to an exact protocol-scoped Key Version, suite, Crypto Policy version, state, and Managed Parameters.
_Avoid_: Protocol key, crypto channel

**Security Association State**:
The shared ground/flight rotation lifecycle `PREINSTALLED -> ACTIVE -> GRACE -> DISABLED`. Only ACTIVE transmits TC; ACTIVE and GRACE may receive during a bounded rollover overlap.
_Avoid_: RX-only compatibility state, key status

**Managed Parameters**:
A direction-specific set of mission-configured CCSDS wire parameters that are not inferred from a transfer frame. Ordinary TC fixes a six-byte SA Nonce Prefix, four-byte IV Counter, and no tag; Recovery TC adds a fixed full-length GCM tag; AOS retains its independently managed sequence, IV, tag, and replay parameters.
_Avoid_: Auto-detected frame settings, cipher options

**SA Nonce Prefix**:
A six-byte value bound to a TC Security Association and never transmitted. Together with SPI and IV Counter it forms either the Recovery TC GCM nonce or the prefix of the Ordinary TC CTR initial counter block.
_Avoid_: Static IV, secret salt

**IV Counter**:
A four-byte TC transmit counter carried in the security header and never reused under the same Security Association. Exhaustion requires activation of a different SPI and key binding.
_Avoid_: Random IV, replay sequence

**Frame Protection**:
The Ordinary TC transmit operation that applies the SPI-bound AES-256-CTR or SM4-CTR suite and emits the fixed SPI-plus-IV-Counter security header without an authentication tag.
_Avoid_: Generic encrypt, wrap frame

**Frame Unprotection**:
The AOS receive operation that resolves the Security Association by SPI, verifies replay and authentication requirements, and returns the recovered transfer frame data.
_Avoid_: Generic decrypt, unpack frame

**Protocol-scoped Key**:
A Key whose use is restricted to a protocol adapter and cannot be invoked through the generic crypto API.
_Avoid_: CCSDS key flag, shared data key

**Replay Window**:
Durable per-association receive state that accepts authenticated out-of-order frames within a bounded window while rejecting duplicates and stale sequence numbers.
_Avoid_: Nonce cache, recent frame list

**TC Ciphertext Acceptance**:
The star-side decision that a no-tag TC frame has valid length and FECF, maps to an enabled Security Association, passes IV-Counter replay checks, decrypts, and passes a mission-owned plaintext validator. It is not cryptographic authentication.
_Avoid_: Authenticated command, verified sender

**Ordinary TC Profile**:
The confidentiality-only TC profile selected by a business SPI and used for normal telecommand traffic. It has a four-byte IV Counter and no authentication tag.
_Avoid_: Default profile, optional-tag TC

**Recovery TC Profile**:
The authenticated-encryption TC profile selected only by a dedicated Recovery SPI and authorized to carry exactly one Root Recovery Transaction. It has a four-byte IV Counter and a full-length GCM tag.
_Avoid_: Tagged ordinary command, optional recovery flag

**Operational Root**:
A protected root secret from which epoch-bound Ordinary TC working keys are derived. A replacement is installed into an inactive root slot before activation.
_Avoid_: Traffic key, uploaded DEK

**Recovery Root**:
An independent protected root secret used only to derive the Recovery TC working key. It cannot be replaced through Recovery TC.
_Avoid_: Backup traffic key, emergency DEK

**Working Key Slot**:
One of three volatile or tightly controlled locations holding the current Ordinary TC key, the next-or-grace Ordinary TC key, or the Recovery TC key.
_Avoid_: Root slot, key archive

**Root Recovery Transaction**:
The single authenticated, encrypted, one-way operation that atomically installs a new Operational Root into the inactive root slot and schedules its activation without exposing any key from flight to ground.
_Avoid_: Generic key upload, key download, remote recovery shell
