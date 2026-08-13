# TPM Providers

- `native`/`tss`/`esapi`: in-process go-tpm production provider; no shell or plaintext temporary files. `PolicyPCR` binds configured PCRs, while a TPM object authorization derived from canonical cluster/node/plane/baseline/policy context binds the remaining context.
- `tpm2-tools`: hardened engineering fallback only.
- `software`/`swtpm`: local tests only and rejected in production configuration.

Native startup fails closed for invalid transports. Tests cover vTPM seal/unseal, context mismatch, restart, and corrupted envelopes when CGO simulator support is available.
