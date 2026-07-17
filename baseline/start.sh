#!/usr/bin/env bash
set -euo pipefail

export PATH=$PATH:/usr/local/go/bin

go mod tidy

export KVLT_HTTP_ADDR="${KVLT_HTTP_ADDR:-0.0.0.0:8080}"
export KVLT_TPM_PROVIDER="${KVLT_TPM_PROVIDER:-tpm2}"
export KVLT_TPM_STATE_DIR="${KVLT_TPM_STATE_DIR:-/tmp/kvlt-tpm}"
export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"
export KVLT_LOG_LEVEL="${KVLT_LOG_LEVEL:-INFO}"
# Database: "memory" (default, non-durable) or "postgres" (durable, design §11).
# When using postgres, set KVLT_DB_DSN to a PostgreSQL connection string, e.g.:
#   postgres://kvlt:secret@localhost:5432/kvlt?sslmode=disable
export KVLT_DB_DRIVER="${KVLT_DB_DRIVER:-postgres}"
export KVLT_DB_DSN="${KVLT_DB_DSN:-postgres://kvlt:secret@localhost:5432/kvlt?sslmode=disable}"
if [ -z "${KVLT_STATIC_TOKENS:-}" ]; then
  export KVLT_STATIC_TOKENS='[
    {
      "token": "admin-token-baseline",
      "tenant_id": "t-admin",
      "scopes": ["keys:create", "keys:read", "keys:manage", "keys:destroy", "tenant:read", "tenant:manage", "audit:read", "audit:manage", "policy:read", "policy:manage", "ops:read"],
      "roles": ["admin"],
      "planes": ["management", "ops"]
    },
    {
      "token": "data-token-baseline",
      "tenant_id": "t-data",
      "scopes": ["crypto:encrypt", "crypto:decrypt"],
      "roles": ["data"],
      "plane": "data"
    },
    {
      "token": "ops-token-baseline",
      "tenant_id": "t-ops",
      "scopes": ["ops:read", "ops:repair"],
      "roles": ["ops"],
      "plane": "ops"
    },
    {
      "token": "admin-data-token-baseline",
      "tenant_id": "t-default",
      "scopes": ["keys:create", "keys:read", "keys:manage", "keys:destroy", "tenant:read", "tenant:manage", "audit:read", "audit:manage", "policy:read", "policy:manage", "crypto:encrypt", "crypto:decrypt", "ops:read", "ops:repair"],
      "roles": ["admin", "data", "ops"],
      "planes": ["management", "data", "ops"]
    }
  ]'
else
  export KVLT_STATIC_TOKENS
fi

echo "$KVLT_STATIC_TOKENS" | jq .

echo "database driver: $KVLT_DB_DRIVER"
mkdir -p "$KVLT_TPM_STATE_DIR" /tmp/kvlt-wal

# Pre-flight: when using postgres, verify it is reachable before building/starting.
if [ "$KVLT_DB_DRIVER" = "postgres" ]; then
  if [ -z "$KVLT_DB_DSN" ]; then
    echo "ERROR: KVLT_DB_DRIVER=postgres but KVLT_DB_DSN is empty."
    echo "Set it to e.g. postgres://kvlt:secret@localhost:5432/kvlt?sslmode=disable"
    exit 1
  fi
  # Extract host:port from DSN for a quick TCP reachability check.
  PG_HOST=$(echo "$KVLT_DB_DSN" | sed -nE 's|.*@([^:/]+)(:[0-9]+)?/.*|\1|p')
  PG_PORT=$(echo "$KVLT_DB_DSN" | sed -nE 's|.*:([0-9]+)/.*|\1|p')
  PG_PORT="${PG_PORT:-5432}"
  if [ -z "$PG_HOST" ]; then PG_HOST="localhost"; fi
  if ! (echo > /dev/tcp/"$PG_HOST"/"$PG_PORT") 2>/dev/null; then
    echo "ERROR: PostgreSQL not reachable at $PG_HOST:$PG_PORT"
    echo "Options:"
    echo "  1. Start PostgreSQL:  sudo systemctl start postgresql"
    echo "  2. Run setup script:  bash setup-postgres.sh"
    echo "  3. Use memory mode:   export KVLT_DB_DRIVER=memory && bash start.sh"
    exit 1
  fi
  if command -v psql >/dev/null 2>&1; then
    if ! pg_isready -h "$PG_HOST" -p "$PG_PORT" >/dev/null 2>&1; then
      echo "WARNING: pg_isready reports PostgreSQL not ready at $PG_HOST:$PG_PORT"
    fi
  fi
  echo "postgres pre-flight OK ($PG_HOST:$PG_PORT)"
fi

echo "building frontend..."
(
  cd web/frontend
  # npm install
  npm run build
)

echo "building backend..."
go build -trimpath -o /tmp/kvlt-baseline ./cmd/key-vault

echo "starting KVLT engineering baseline on $KVLT_HTTP_ADDR"
exec /tmp/kvlt-baseline
