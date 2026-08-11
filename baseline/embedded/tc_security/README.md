# Flight TC security module

This freestanding C11 module receives complete TC transfer frames and implements the fixed mission profile:

- ordinary Current/Next: SM4-HCTR, 4-byte transmitted IV, no tag;
- recovery Root Prepare: SM4-GCM, 4-byte IV and 16-byte tag;
- CMAC counter KDF from independent Operational and Recovery roots;
- 64-frame replay window and a 4096 ordinary-IV forward-jump cap;
- automatic Next-SPI promotion after full plaintext validation;
- complete 16-bit SPI space with `Next = (Current + 1) mod 65536`;
- durable Pending Root restore across reset;
- no Previous/Grace state and no compatibility parser.

The caller supplies only two integration callbacks: a complete ordinary plaintext validator and an atomic state commit adapter. Plaintext is released only after both succeed. Root Prepare plaintext is consumed internally.

The production plaintext validator is owned by flight software and must implement
the closed contract in
[`../../docs/TC_PLAINTEXT_VALIDATION_DESIGN.md`](../../docs/TC_PLAINTEXT_VALIDATION_DESIGN.md).
The `CA FE` check in the C test harness is only a test double; it is forbidden in
production builds and is not release evidence.

The integration surface is `tcsec_init`, `tcsec_reset`, `tcsec_receive`, and
`tcsec_deinit`.
`tcsec_status_string` is a diagnostic helper. The required callback types are
`tcsec_plaintext_validator_fn` and `tcsec_state_commit_fn`.
`tcsec_init` accepts them as one `tcsec_callbacks_t` value and copies that value
into the caller-owned context; no separate bind/unbind lifecycle exists.

`tcsec_reset` reloads a complete durable configuration while retaining the
callbacks and caller binding established by `tcsec_init`. It has transactional
failure semantics: invalid or non-derivable replacement state leaves the old
initialized context usable. It does not write NVM or silently clear replay.

The module has no mutable global state. Distinct caller-owned
`tcsec_context_t` objects may be used concurrently or through nested callbacks.
A single context owns one replay and rotation state machine, so the flight
software must serialize calls on that same context and must not re-enter it
from its callbacks.

## Fixed SEU hardening

The module has one fixed Balanced hardening contract. It is not part of
`tcsec_config_t` and cannot be weakened at runtime or by feature macros:

- CRC32C plus inverse protects the live context and is checked at every public
  entry and after callbacks;
- every traffic-key derivation is performed twice and compared;
- every replay decision and next-state calculation is performed twice and
  compared field by field;
- Recovery GCM authentication/decryption is performed twice and compared;
- ordinary plaintext is CRC32C-protected across the persistence callback.

The High-profile HCTR decrypt/re-encrypt round trip is intentionally absent: it
would add a second HCTR pass and one maximum-frame temporary buffer while still
not replacing cryptographic authentication. Frame bounds, fixed suites, FECF,
plaintext validation, atomic commit-before-release, error-path zeroization, and
fail-closed SPI/configuration handling remain unconditional safety invariants.
ECC/EDAC, memory scrubbing, MPU, watchdog, executable-image checking, and the
physical NVM redundancy strategy remain platform/BSP responsibilities.

Build and run the shared Go/C vectors:

```sh
make test
```

The two current vector files live in `../../testdata` and cover SM4-HCTR
ordinary protection plus authenticated SM4-GCM Root Prepare.
