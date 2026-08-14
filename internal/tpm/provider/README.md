# TPM Providers

- `native`: the only production provider. It uses in-process go-tpm with no
  shell or plaintext temporary files. A mandatory `PolicyPCR` binds the object;
  a dedicated non-root service account and restricted raw TPM device enforce
  the local host boundary.
- `swtpm`: the only test provider and always rejected in production.

Native startup fails closed for invalid devices, root execution, obsolete
sealed-object formats, PCR mismatch, context mismatch, and corrupted envelopes.
The retired tpm2-tools and provider-alias paths are not accepted.
