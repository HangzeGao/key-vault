# Production Security Gate

The current design is single-host and intentionally avoids a database service.
Production uses an absolute SQLite path on protected local storage and a native
TSS/ESAPI TPM. SQLite runs in WAL mode with `synchronous=FULL`; all security
state changes use immediate transactions.

Configuration fails closed unless production supplies:

- an absolute `database.path` on a restricted, monitored filesystem;
- native TPM access with an explicit TCTI and approved PCR policy;
- TLS 1.3 server credentials and a client CA for mTLS;
- OIDC/JWT issuer, audience, HTTPS JWKS, asymmetric algorithms, and short token lifetime;
- signed policy trust files, an audit-redaction pepper, and restore-drill evidence;
- one selected listener plane per process and deployment-enforced interface isolation.

Static tokens, HMAC, software/shell TPM providers, plain HTTP, wildcard CORS,
unknown configuration fields, and relative production state paths are rejected.

## Backup and restore rule

Use a SQLite online-backup operation or a filesystem snapshot that is explicitly
SQLite/WAL-aware. Back up the database and TPM provider state as one recovery
set. A restored TC counter snapshot must never transmit under its old
operational SPI: recovery completes by provisioning or activating a new
operational root/SPI/epoch before TC traffic resumes. Keep offline copies of
mission root-recovery material and signed provisioning evidence outside the host.

## Release blockers

Before launch, verify native TPM PCR-change/restart behavior, SQLite corruption
and disk-full failure, concurrent counter allocation, online backup/restore,
forced new-SPI recovery, JWT/JWKS rotation, certificate rotation, and end-to-end
ground/flight vectors. Audit logs and crash artifacts must be scanned for
tokens, plaintext frames, root keys, working keys, and wrapped-material blobs.
