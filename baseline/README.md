# CCSDS Ground Cryptographic System

This repository is the pre-production ground implementation for mission-scoped
CCSDS link security. Its public contract is intentionally small:

- Complete TC frame protection with ordinary SM4-HCTR and Recovery SM4-GCM profiles.
- Provisional AOS cryptographic processing; the complete-frame wire contract remains blocked until the mission AOS format is frozen.
- Offline creation of protocol roots and Security Associations.
- Read-only audit, health, database, and association operations views.
- TPM-sealed Cryptographic Root Key (CRK); protocol roots are persisted only as wrapped material.
- One local SQLite `SecurityState` store for associations, counters, replay windows, sealed envelopes, and audit chains.

Generic key CRUD, arbitrary-data crypto, key upload/download, lifecycle jobs,
outbox processing, PostgreSQL, and volatile repository modes are not part of
the current contract.

## Start

```bash
export KVLT_MISSION_PROFILE=/secure/path/mission-security.yaml
bash start.sh provision-ccsds
bash start.sh
```

Provisioning consumes one strict Mission Security Profile and writes three
private artifacts below `KVLT_PROVISION_ARTIFACTS_DIR`: the initial flight NVM
image, the authenticated Root Prepare TC frame, and a non-secret hash evidence
record. The example profile contains public test roots and is never flight-safe.

After the Recovery frame has been scheduled, the approved ground-local switch is:

```bash
go run ./cmd/ccsds-activate -tenant t-default -reason "scheduled rotation" -ticket-id CHG-1234
```

It accepts only a persisted `PREPARED` rotation, records requested/succeeded or
failed audit events, and moves the ground state to `SWITCHING`. The first
successfully protected Next-SPI frame records `ACTIVE` ground evidence.

`start.sh` keeps all durable engineering state below `baseline/state/` by
default. Override the directory with `KVLT_STATE_DIR`, or only the database
file with `KVLT_STATE_DB`. No runtime state is placed in `/tmp`.

Open <http://localhost:8080/ui/login>. The Data interface listens on port 8081.
Development credentials are:

| Purpose | Token |
| --- | --- |
| TC protect / AOS unprotect | `mission-data-token-baseline-000001` |
| Mission operations console | `mission-console-token-baseline-0001` |

Production replaces these examples with independent 256-bit random tokens in a
0600 file. HTTPS uses one server certificate; callers pin its public-key
fingerprint. No client CA, client certificate, JWT issuer, or HMAC key is used.

## Verify

```powershell
make release-gate

cd web/frontend
npm ci
npm run test
npm run build
```

`release-gate` runs all Go tests, the API-to-flight shared vector, the C and Go
95% coverage gates, ARMv7 cross compilation, QEMU/NEON flight tests, a
Go/x86-C/ARMv7-C differential corpus, and frontend tests/build, then writes a hash-bound evidence
record below `build/release/`. Ordinary test success alone is not release evidence.

## HTTP Contract

| Entry point | Purpose |
| --- | --- |
| `GET /healthz` | Process liveness |
| Data `POST /ui/api/v1/ccsds/tc:protect` | Transform one complete plain TC frame into a complete protected frame |
| Data `POST /ui/api/v1/ccsds/aos:unprotect` | Provisional AOS decrypt endpoint; not a frozen release contract |
| Data `POST /ui/api/v1/ccsds/flight-status:observe` | Submit carrier-independent flight crypto status extracted by the housekeeping/AOS adapter |
| Ops `GET /ui/api/v1/audit/*` | Read and verify audit chains |
| Ops `GET /ui/api/v1/ops/health` | TPM, policy, and SQLite readiness |
| Ops `GET /ui/api/v1/ops/db/status` | Redacted local-state diagnostics |
| Ops `GET /ui/api/v1/ops/ccsds/status` | Ground/flight profile, Security Association, counter, self-test and timing reconciliation |

See [CCSDS Link Security](docs/CCSDS_LINK_SECURITY.md),
[Ground/Flight Architecture](docs/TC_GROUND_FLIGHT_ARCHITECTURE.md),
[Cryptographic Test Design](docs/CRYPTOGRAPHIC_TEST_DESIGN.md), and
[Production Security Gate](docs/PRODUCTION_SECURITY.md).
