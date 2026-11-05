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

The caller supplies an atomic state commit adapter and may supply a monotonic
microsecond clock. Current-SPI plaintext is delivered after replay is persisted. Flight
software validates and dispatches the command. Next-SPI plaintext also passes
internal frame and packet checks plus a statically linked mission policy before
promotion. Root Prepare plaintext is consumed internally. The clock measures
processing time and records clock faults. Without it, receive attempts are
still counted and all four timing fields remain zero.

Flight software supplies the mission policy at build time through the private
`src/next_validation.h` contract. A flight build must link the mission's
`tcsec_mission_next_command_allowed` implementation. The repository test policy
is enabled only in test builds. See
[`../../docs/TC_PLAINTEXT_VALIDATION_DESIGN.md`](../../docs/TC_PLAINTEXT_VALIDATION_DESIGN.md).

Flight applications include `tc_security.h` for the four `tcsec_*` operations.
Pass a zero-initialized context and register the required `load_state` and
`commit_state` callbacks with `tcsec_init`. Each callback clears its own
temporary secret data on every return path. Timing is optional. The status-to-string helper
is in `tools/tc_security_diagnostics.h`.

`tcsec_reset` reloads a complete durable configuration using the bound
callbacks. A failed reload or commit I/O failure pauses reception until a
reset succeeds. The context is an opaque, caller-owned 512-byte object that
lives for the computer runtime. Callback bindings remain fixed. Storage callbacks
and their helpers clear their own temporary secrets before returning. The core
clears the loaded configuration after use and manages its internal key material.
The storage callback owns the persistence policy and format.

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

`make` or `make core` builds `build/libtc_security.a`. At final link, flight
software supplies the mission policy. On initialization it registers its
storage callbacks. First installation provisions the mission's initial
security state through the authorized flight commissioning process.
Operational startup and reset load the verified state through `load_state`.
The flight storage service owns authentication, confidentiality, rollback
protection and crash recovery for its data.

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

## Flight delivery and persistent reliability

`make flight-package MISSION_POLICY=<approved-source>` packages only the public
`tc_security.h` and target `libtc_security.a`, with build metadata and hashes.
The policy is compiled into the archive. No test policy is permitted in this
target. The compiler, ABI and approved mission rules must be frozen for delivery.

The flight storage callback owns three independently writable record lanes and
an independently protected, atomic, anti-rollback commit anchor. Each transaction
retains anchored records, verifies all three candidate copies, then publishes the
anchor. Loading requires two exact matching copies of the anchored version and
repairs one failed lane before further commits. No older majority may override
the anchor. This is a platform contract, not a physical NVM driver in the core.
The test-only model injects cuts at every payload byte and publication step for
replay, prepare and promotion; actual media and power-cut testing remain required.

See the flight manual sections 3, 6 and appendix B for error handling, power loss,
the business-execution window, callbacks and the implementation guide.
