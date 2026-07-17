# Production Security Verification

Production requires `environment: production`, PostgreSQL, physical plane isolation, and the native TPM provider; startup rejects memory, software, swtpm, and tpm2-tools modes.

Release validation must scan logs, structured errors, audit metadata, UI snapshots, database dumps, and temporary directories for tokens, plaintext, DEK/CRK, full envelopes, wrapped material, and authorization headers. Exercise failed database connections, migrations, concurrent updates, transaction rollback, backup/restore, invalid TCTI/policy, TPM restart, and corrupted CRK envelopes. Ops mutations must demonstrate requested/final audit pairs and fail closed when either audit write is unavailable.
