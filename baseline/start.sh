#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:/usr/local/go/bin"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-serve}"
if [ "$MODE" != "serve" ] && [ "$MODE" != "provision-ccsds" ]; then
  echo "usage: bash start.sh [serve|provision-ccsds]"
  exit 2
fi

export KVLT_HTTP_ADDR="${KVLT_HTTP_ADDR:-0.0.0.0:8080}"
# Node identity, SQLite state, and TPM state remain stable across restarts.
export KVLT_NODE_ID="${KVLT_NODE_ID:-node-bootstrap}"
export KVLT_STATE_DIR="${KVLT_STATE_DIR:-$SCRIPT_DIR/state}"
export KVLT_STATE_DB="${KVLT_STATE_DB:-$KVLT_STATE_DIR/security-state.db}"
export KVLT_TPM_PROVIDER="${KVLT_TPM_PROVIDER:-tpm2}"
export KVLT_TPM_STATE_DIR="${KVLT_TPM_STATE_DIR:-$KVLT_STATE_DIR/tpm}"
export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"
export KVLT_LOG_LEVEL="${KVLT_LOG_LEVEL:-INFO}"

if [ -z "${KVLT_STATIC_TOKENS:-}" ]; then
  export KVLT_STATIC_TOKENS='[
    {
      "token": "mission-data-token-baseline",
      "tenant_id": "t-default",
      "scopes": ["ccsds:tc:protect", "ccsds:aos:unprotect"],
      "roles": ["data"],
      "plane": "data"
    },
    {
      "token": "mission-console-token-baseline",
      "tenant_id": "t-default",
      "scopes": ["ccsds:tc:protect", "ccsds:aos:unprotect", "audit:read", "ops:read"],
      "roles": ["admin", "data", "ops"],
      "planes": ["management", "data", "ops"]
    }
  ]'
fi

echo "$KVLT_STATIC_TOKENS" | jq -e 'type == "array" and length == 2' >/dev/null
echo "static token configuration: 2 mission-scoped principals loaded"
echo "security state: $KVLT_STATE_DB"
echo "node id: $KVLT_NODE_ID"
mkdir -p "$KVLT_STATE_DIR" "$KVLT_TPM_STATE_DIR" "$SCRIPT_DIR/bin"
chmod 700 "$KVLT_STATE_DIR" "$KVLT_TPM_STATE_DIR"

cd "$SCRIPT_DIR"
if [ "$MODE" = "provision-ccsds" ]; then
  if [ -z "${KVLT_MISSION_PROFILE:-}" ]; then
    echo "KVLT_MISSION_PROFILE must point to the controlled Mission Security Profile" >&2
    exit 2
  fi
  KVLT_PROVISION_ARTIFACTS_DIR="${KVLT_PROVISION_ARTIFACTS_DIR:-$KVLT_STATE_DIR/provisioning-artifacts}"
  echo "building offline CCSDS provisioner..."
  go build -trimpath -o bin/ccsds-provision ./cmd/ccsds-provision
  echo "provisioning paired ground and flight TC security state..."
  exec "$SCRIPT_DIR/bin/ccsds-provision" \
    -mission-profile "$KVLT_MISSION_PROFILE" \
    -artifacts-dir "$KVLT_PROVISION_ARTIFACTS_DIR"
fi

echo "building frontend..."
(
  cd web/frontend
  npm run build
)

echo "building backend..."
go build -trimpath -o bin/key-vault ./cmd/key-vault

echo "starting KVLT engineering baseline on $KVLT_HTTP_ADDR"
exec "$SCRIPT_DIR/bin/key-vault"
