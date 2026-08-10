# CCSDS Ground Cryptographic System

This repository is the pre-production ground implementation for mission-scoped
CCSDS link security. Its public contract is intentionally small:

- TC frame-data-field protection with ordinary CTR and Recovery GCM profiles.
- AOS transfer-frame authenticated decryption with GCM.
- Offline creation of protocol roots and Security Associations.
- Read-only audit, health, database, and association operations views.
- TPM-sealed Cryptographic Root Key (CRK); protocol roots are persisted only as wrapped material.
- One local SQLite `SecurityState` store for associations, counters, replay windows, sealed envelopes, and audit chains.

Generic key CRUD, arbitrary-data crypto, key upload/download, lifecycle jobs,
outbox processing, PostgreSQL, and volatile repository modes are not part of
the current contract.

## Start

```bash
bash start.sh provision-ccsds
bash start.sh
```

`start.sh` keeps all durable engineering state below `baseline/state/` by
default. Override the directory with `KVLT_STATE_DIR`, or only the database
file with `KVLT_STATE_DB`. No runtime state is placed in `/tmp`.

Open <http://localhost:8080/ui/login>. Development credentials are:

| Purpose | Token |
| --- | --- |
| TC protect / AOS unprotect | `mission-data-token-baseline` |
| Mission operations console | `mission-console-token-baseline` |

These static tokens, plain HTTP, and shell TPM access are development-only.

## Verify

```powershell
$env:GOCACHE="$PWD/.cache/go-build"
go test ./...

cd web/frontend
npm ci
npm run test
npm run build
```

## HTTP Contract

| Entry point | Purpose |
| --- | --- |
| `GET /healthz` | Process liveness |
| `POST /ui/api/v1/ccsds/tc:protect` | Protect one TC frame data field |
| `POST /ui/api/v1/ccsds/aos:unprotect` | Authenticate and decrypt one AOS frame |
| `GET /ui/api/v1/audit/*` | Read and verify audit chains |
| `GET /ui/api/v1/ops/health` | TPM, policy, and SQLite readiness |
| `GET /ui/api/v1/ops/db/status` | Redacted local-state diagnostics |
| `GET /ui/api/v1/ops/ccsds/status` | Security Association and counter state |

See [CCSDS Link Security](docs/CCSDS_LINK_SECURITY.md),
[Ground/Flight Architecture](docs/TC_GROUND_FLIGHT_ARCHITECTURE.md), and
[Production Security Gate](docs/PRODUCTION_SECURITY.md).
