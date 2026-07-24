# KVLT Key Vault - Engineering Baseline

This directory contains the single engineering baseline implementation for the TPM 2.0 based key vault. The repository no longer maintains separate staged application trees.

Implemented baseline capabilities:

- Key lifecycle: create, import path, query, enable, disable, rotate, and schedule destroy.
- Server-side Encrypt/Decrypt and batch Encrypt/Decrypt.
- AES/SM4 policy suites with algorithm and mode bound to each key.
- Envelope v1 and canonical AAD.
- TPM-backed key boundary: plaintext key material is not returned by API responses.
- Protocol-neutral Key Encryption Key (KEK) upload/download with staged confirmation and activation.
- Logical isolation for management, data, ops, key, and audit planes.
- Hash-chained audit, lifecycle worker, signed policy reload, and tenant envelope configuration.
- Embedded React UI served under `/ui/`.

Current engineering limits:

- The in-memory repository is suitable for the current baseline and automated verification, not for durable production storage.
- Static demo tokens are for isolated development only.
- Trusted-node and attestation workflows are intentionally not part of this baseline.
- Client DataKey or plaintext key export is intentionally not provided.

## Docker

```powershell
cd baseline
docker compose up --build -d
docker compose ps
```

Open <http://localhost:8080/ui/login>.

Demo tokens:

| Plane | Token |
| --- | --- |
| Management | `admin-token-baseline` |
| Data | `data-token-baseline` |
| Ops | `ops-token-baseline` |
| Management + Data + Ops | `admin-data-token-baseline` |

## Local Build

```powershell
cd baseline
go test ./...

cd web/frontend
npm ci
npm run build
```

## HTTP Entry Points

| Entry point | Description |
| --- | --- |
| `GET /healthz` | Unauthenticated health check |
| `GET /ui/login` | Embedded web UI |
| `/ui/api/v1/keys` | Management API |
| `/ui/api/v1/key-uploads*` | KEK key upload management API |
| `/ui/api/v1/key-downloads*` | KEK key download/import management API |
| `/ui/api/v1/crypto/*` | Data-plane crypto API |
| `/ui/api/v1/audit/*` | Audit API |
| `/ui/api/v1/policies*` | Policy governance API |
| `/ui/api/v1/lifecycle/*` | Lifecycle worker status API |
| `/ui/api/v1/ops/*` | Ops-plane database operations API |
