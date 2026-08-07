# CCSDS link-security profiles

The CCSDS module sits above the protocol-neutral raw protection module. It owns
transfer-frame layout, SPI/Security Association selection, transmitted counters,
FECF processing, and replay state. Key/policy resolution and primitives remain
inside the raw protection module.

## Confirmed TC transmit profile

The current TC profile is fixed and has no compatibility path to the earlier
provisional layout:

```text
TC primary header (5)
|| SPI (2)
|| IV_COUNTER (4)
|| CTR ciphertext (N)
|| FECF (2)
```

- TC accepts exactly `AES_256_CTR` or `SM4_CTR` (`ENCRYPT_ONLY`). The SPI-bound
  SA selects the algorithm; no algorithm identifier is added to the frame.
- Encryption covers the complete original TC data field.
- The six-byte security header is exactly `SPI || IV_COUNTER`.
- There is no authentication tag or cryptographic check field.
- FECF is calculated over the final secured frame excluding the FECF itself.
- The primary-header frame-length field describes the final secured frame.
- Maximum final TC frame length is 1024 bytes.

The AES/SM4-CTR initial counter is:

```text
SA_NONCE_PREFIX[6] || SPI[2] || IV_COUNTER[4] || BLOCK_COUNTER[4]
```

The SA nonce prefix is provisioned with the key binding and is not transmitted.
The per-frame block counter starts at zero. PostgreSQL allocates IV counters
atomically in the range `0..2^32-1`; exhaustion requires a new SA/key binding.

Ground and flight use the same rollover states: `PREINSTALLED`, `ACTIVE`,
`GRACE`, and `DISABLED`. Ground TC transmits only with ACTIVE; receivers accept
ACTIVE and GRACE during a bounded rollover overlap. The obsolete provisional
`RX_ONLY` state is not accepted.

Because no tag exists, this profile provides confidentiality only. SPI, IV,
ciphertext, and FECF are attacker-modifiable. IV processing can reject exact
duplicates but cannot be described as authenticated anti-replay.

## AOS receive profile

AOS receive remains independently configured because its final mission wire
layout is not yet fixed. It retains exact suite-bound sequence, full IV, tag,
and replay-window parameters. TC fixed fields are not generalized into AOS.

## Proposed root-recovery profile

`TC_RECOVERY_PROFILE.md` proposes a second, dedicated SPI-selected TC profile
with a full GCM tag for exactly one root-recovery transaction. It is a design
proposal and is not part of the current implementation. Ordinary TC remains the
strict no-tag CTR profile; no optional-tag branch is proposed.

## Ground/flight interoperability

`testdata/ccsds_tc_aes256_ctr.txt` and `testdata/ccsds_tc_sm4_ctr.txt` are the
canonical ground-to-flight vectors. The Go CCSDS test generates and compares
the secured frames; the embedded C test decrypts both algorithms and validates
the recovered TC data field.

The flight implementation lives in `embedded/tc_security` and deliberately
does not include ground-only management, persistence technologies, generic
protocol registries, or unused algorithm modes.

## Remaining mission decisions

- command-format and state validator rules after CTR decryption;
- platform adapter for atomic replay-state persistence and flash-wear strategy;
- trusted key-slot provisioning and state transition procedure;
- clear/recovery routing outside the encrypted receiver;
- final AOS frame profile and authoritative interoperability vectors.
