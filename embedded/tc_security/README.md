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

The caller supplies three platform callbacks: a complete ordinary plaintext
validator, an atomic state commit adapter, and a monotonic microsecond clock.
Plaintext is released only after validation and persistence both succeed. Root
Prepare plaintext is consumed internally. The clock is used only for redacted
runtime timing counters; it is not part of nonce, replay, or key derivation.

The production plaintext validator is owned by flight software and must implement
the closed contract in
[`../../docs/TC_PLAINTEXT_VALIDATION_DESIGN.md`](../../docs/TC_PLAINTEXT_VALIDATION_DESIGN.md).
The `CA FE` check in the C test harness is only a test double; it is forbidden in
production builds and is not release evidence.

The integration surface is `tcsec_init`, `tcsec_reset`, `tcsec_receive`,
`tcsec_get_runtime_status`, and `tcsec_deinit`.
`tcsec_status_string` is a diagnostic helper. The required callback types are
`tcsec_plaintext_validator_fn`, `tcsec_state_commit_fn`, and
`tcsec_monotonic_time_us_fn`.
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

## ARMv7 SM4 acceleration

ARMv7 targets build both the software SM4 implementation and the ARMv7/NEON
assembly adapter. Linux selects NEON from `AT_HWCAP/HWCAP_NEON`; freestanding
ARMv7 builds compiled with NEON select it from the target capability. A target
without NEON always uses software. This selection is internal to each expanded
SM4 key and requires no flight-software callback or `tcsec_*` configuration.
Consequently SM4-HCTR, Recovery SM4-GCM, and CMAC KDF share the same automatic
selection.

`make print-backend` reports which implementations are in the binary. Set
`ARMV7_NEON=0` only for an explicit software-only build, or `ARMV7_NEON=1` for
an ARMv7 cross build whose compiler target has NEON enabled. QEMU/KAT validates
instruction correctness; final-board WCET, throughput, and side-channel
evidence remain release requirements.

`tcsec_init` runs SM4 block, CMAC-KDF, HCTR, and authenticated GCM known-answer
tests through the backend selected on that target before loading mission roots.
Failure leaves the context in `TCSEC_SELF_TEST_LOCKED`; `receive` and `reset`
cannot bypass it. `tcsec_get_runtime_status` exposes only the self-test/backend,
Mission Profile digest, SPI/epoch/root versions, pending-root flag, receive
counts and timing counters. It never exposes roots, working keys, nonce prefixes
or replay bitmaps.

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

`tc_security_nvm.h` supplies the fixed 175-byte, endian-stable two-slot state
codec used at the BSP seam. Every slot carries a monotonic generation, Mission
Security Profile SHA-256 digest, CRC32C and its inverse. Decode validates the
complete `tcsec_config_t`; selection accepts the newest valid slot, falls back
after an interrupted/corrupt write, rejects ambiguous equal generations, and
enforces a caller-provided rollback floor. The BSP still owns physical erase,
write, read-back and storage of the trusted generation floor. CRC detects
accidental corruption; it is not an authenticity mechanism, so only trusted
flight software may write these slots.
When exactly one slot is invalid, `tcsec_nvm_plan_repair` returns a complete
next-generation replacement targeting the bad slot. The BSP performs the
physical atomic write and read-back verification before advancing its trusted
generation floor.

Build and run the shared Go/C vectors:

```sh
make test
```

The two current vector files live in `../../testdata` and cover SM4-HCTR
ordinary protection plus authenticated SM4-GCM Root Prepare.

`../../testdata/crypto/cryptography-sm4-v1.tsv` adds an independent external
oracle layer. It contains 28 public TEST ONLY records generated by pinned
`pyca/cryptography 49.0.0` with its OpenSSL 4.0.1 backend plus the normative
RFC 8998 SM4-GCM vector. `make test` compiles a flight-C harness that consumes
the same records as the ground Go test. The vector file, every row, and the
generator source carry a SHA-256 integrity value; regeneration tooling is
under `scripts/oracle`.

`scripts/armv7_gate.sh` additionally generates deterministic Go reference
vectors and verifies them with x86 C software and ARMv7/NEON C under QEMU. The
release gate fails if the cross toolchain, QEMU, sysroot, backend identity, full
flight suite, or any differential record is missing.
