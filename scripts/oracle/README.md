# External cryptographic vector generator

`cryptography_vector_generator.py` is an offline test oracle. It invokes the
SM4 and CMAC primitives from pinned `pyca/cryptography 49.0.0`, backed by its
bundled OpenSSL 4.0.1. The generator contains no SM4 implementation and shares
no cryptographic source with the Go or flight C products.

SM4-GCM uses the normative RFC 8998 Appendix A.1 vector. SM4-HCTR is a fixed
GB/T 17964 project profile rather
than an OpenSSL mode. Its short, auditable composition is implemented in the
generator while all block-cipher operations come from OpenSSL; these records
are therefore classified `INDEPENDENT`, not `NORMATIVE`.

The committed TSV is the normal offline test input. Its header binds the exact
generator source SHA-256, and the Go gate verifies that binding. Regeneration
requires a matching `pyca/cryptography` runtime:

```bash
python3 scripts/oracle/cryptography_vector_generator.py \
  testdata/crypto/cryptography-sm4-v1.tsv
```

The separate `aes_downlink_vectors.py` pins cryptography 50.0.2 / OpenSSL 4.0.3
and first checks NIST SP 800-38A F.1.5. It generates four normative blocks and
379 independent 880-byte AES-256-ECB data fields, including every key bit and
every data block. It never imports product code. Regenerate with:

```bash
python3 scripts/oracle/aes_downlink_vectors.py testdata/crypto/aes-downlink-v1.tsv
```

Both vector sets use the same 18-column manifest; file, row and generator
SHA-256 are verified by their Go consumers. Committed offline fixtures suffice
for normal gates; installing either generator's Python runtime is unnecessary.
