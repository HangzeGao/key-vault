# Flight TC security module

This freestanding C11 module receives complete TC transfer frames and implements the fixed mission profile:

- ordinary Current/Next: AES-256-CTR or SM4-CTR, 4-byte transmitted IV, no tag;
- recovery Root Prepare: AES-256-GCM or SM4-GCM, 4-byte IV and 16-byte tag;
- CMAC counter KDF from independent Operational and Recovery roots;
- 64-frame replay window and a 4096 ordinary-IV forward-jump cap;
- automatic Next-SPI promotion after full plaintext validation;
- complete 16-bit SPI space with `Next = (Current + 1) mod 65536`;
- durable Pending Root restore across reset;
- no Previous/Grace state and no compatibility parser.

The caller supplies only two integration callbacks: a complete ordinary plaintext validator and an atomic state commit adapter. Plaintext is released only after both succeed. Root Prepare plaintext is consumed internally.

The integration surface is `tcsec_init`, `tcsec_receive`, and `tcsec_clear`.
`tcsec_status_string` is a diagnostic helper. The required callback types are
`tcsec_plaintext_validator_fn` and `tcsec_state_commit_fn`.

Build and run the shared Go/C vectors:

```sh
make test
```

The four vector files live in `../../testdata` and cover AES/SM4 ordinary encryption plus AES/SM4 authenticated Root Prepare.
