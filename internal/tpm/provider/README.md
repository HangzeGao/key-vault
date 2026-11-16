# TPM Providers

- `native`: the only production provider. It uses in-process go-tpm with no
  shell or plaintext temporary files. Salted AES-CFB sessions protect random
  material and unsealed data in TPM responses and sensitive data in create
  commands. A mandatory production `PolicyPCR` binds the sealed object. A
  dedicated non-root service account and restricted TPM device enforce the
  local host boundary. The TPM channel protection assumes an authentic storage
  primary public key. The authorized host process handles plaintext in memory.
- `swtpm`: the only test provider and always rejected in production.

Native startup fails closed for invalid devices, root execution, obsolete
sealed-object formats, PCR mismatch, context mismatch, and corrupted envelopes.
The retired tpm2-tools and provider-alias paths are not accepted.
