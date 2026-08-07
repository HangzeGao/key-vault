# KVLT Key Vault - Engineering Baseline

This directory contains the single engineering baseline implementation for the TPM 2.0 based key vault. The repository no longer maintains separate staged application trees.

Implemented baseline capabilities:

- Key lifecycle: create, import path, query, enable, disable, rotate, and schedule destroy.
- Server-side encryption/decryption and detached authentication/verification.
- A closed service mapping: `AUTH_ONLY` → CMAC, `ENCRYPT_ONLY` → CTR, and
  `AUTH_ENCRYPT` → GCM, for both AES and SM4 suites.
- Envelope v1 and canonical AAD.
- TPM-backed key boundary: plaintext key material is not returned by API responses.
- Protocol-neutral Key Encryption Key (KEK) upload/download with staged confirmation and activation.
- Process-scoped HTTP route isolation for management, data, and ops planes,
  plus internal key-resolver and audit module boundaries.
- Hash-chained audit, lifecycle worker, signed policy reload, and tenant envelope configuration.
- Embedded React UI served under `/ui/`.

Current engineering limits:

- The in-memory repository is suitable for the current baseline and automated verification, not for durable production storage.
- Static demo tokens are for isolated development only.
- Trusted-node and attestation workflows are intentionally not part of this baseline.
- Client DataKey or plaintext key export is intentionally not provided.
- A separately deployed Key Plane, transactional CRK rotation, and node-specific
  CRK envelope distribution remain production blockers. See
  [Production Security Gate](docs/PRODUCTION_SECURITY.md).

## Docker

```powershell
cd baseline
docker compose up --build -d
docker compose ps
```

Open <http://localhost:8080/ui/login>.

This Compose profile is development-only. It intentionally uses plain HTTP,
static tokens, and a non-production TPM provider.

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

Production configuration shape: [config.production.example.yaml](config.production.example.yaml).
Protection-mode contracts and examples: [Crypto Modes](docs/CRYPTO_MODES.md).

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
