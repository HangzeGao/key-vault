# Production Security Gate

The current design is single-host and intentionally avoids a database service.
Production uses an absolute SQLite path on protected local storage and a native
TSS/ESAPI TPM. SQLite runs in WAL mode with `synchronous=FULL`; all security
state changes use immediate transactions.

Configuration fails closed unless production supplies:

- an absolute `database.path` on a restricted, monitored filesystem;
- native TPM access with an explicit TCTI and approved PCR policy;
- TLS 1.3 server credentials whose leaf certificate is pinned by callers;
- one exact Data source IP, an explicit local Data bind address, and a matching pre-TLS host-firewall rule;
- one controlled verifier file containing only SHA-256 verifiers for independent 256-bit Data and Ops tokens;
- signed policy trust files, an audit-redaction pepper, and restore-drill evidence;
- separate Data and Ops listener addresses in the single runtime process.

The native TPM provider runs only as a dedicated non-root service account. Its
TCTI is a raw absolute character-device path (normally `/dev/tpmrm0`), never a
symlink; the device may be owned by the service account or by a dedicated group
containing only that account, and must have no permissions for other users.
PCR policy is mandatory and non-empty. The process no longer uses a publicly
derivable context value as a TPM password: sealed objects are protected by the
PCR policy and this host access boundary. Host root remains part of the trusted
computing base; excluding a hostile root would require an external approval
factor or a hardware boundary with independently administered authorization.

The TLS private key, token-verifier file, audit-redaction pepper, and
restore-drill evidence must be regular non-symlink files owned by the service
account with no group or other permission bits (`0600` or stricter). The
certificate, signed policy, and policy trust keys are public verification
material and only require readable regular files. Production startup fails on
platforms where the service cannot verify POSIX ownership and mode bits.

Example tokens, software/shell TPM providers, plain HTTP, wildcard CORS,
wildcard Data listeners, CIDR/proxy-derived source addresses, unknown
configuration fields, and relative production state paths are rejected. The
Data listener has no unauthenticated health route; liveness exists only on the
loopback Ops listener.

Generate and install the fixed access bundle using
[`ACCESS_CONTROL_USER_MANUAL.md`](ACCESS_CONTROL_USER_MANUAL.md). Raw bearer
tokens are never loaded by the server and there is no environment-token,
online-issuer, refresh-token or grace compatibility path.

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
forced new-SPI recovery, access-token rotation, certificate rotation, firewall/source-IP enforcement, and end-to-end
ground/flight vectors. Audit logs and crash artifacts must be scanned for
tokens, plaintext frames, root keys, working keys, and wrapped-material blobs.
