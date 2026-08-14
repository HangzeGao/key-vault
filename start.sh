#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:/usr/local/go/bin"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-}"
if [ "$MODE" != "serve" ] && [ "$MODE" != "provision-ccsds" ]; then
  echo "usage: bash start.sh serve /absolute/path/config.yaml | provision-ccsds" >&2
  exit 2
fi

cd "$SCRIPT_DIR"
if [ "$(go env GOVERSION)" != "go1.26.6" ]; then
  echo "Go 1.26.6 is required" >&2
  exit 2
fi

if [ "$MODE" = "provision-ccsds" ]; then
	if [ "$#" -ne 1 ]; then
		echo "provision-ccsds accepts no positional arguments" >&2
		exit 2
	fi
  if [ -z "${KVLT_MISSION_PROFILE:-}" ]; then
    echo "KVLT_MISSION_PROFILE must point to the controlled Mission Security Profile" >&2
    exit 2
  fi
	if [ -z "${KVLT_PROVISION_ARTIFACTS_DIR:-}" ]; then
		echo "KVLT_PROVISION_ARTIFACTS_DIR must be explicitly configured" >&2
		exit 2
	fi
  echo "building offline CCSDS provisioner..."
	mkdir -p "$SCRIPT_DIR/bin"
  go build -trimpath -o bin/ccsds-provision ./cmd/ccsds-provision
  echo "provisioning paired ground and flight TC security state..."
  exec "$SCRIPT_DIR/bin/ccsds-provision" \
    -mission-profile "$KVLT_MISSION_PROFILE" \
    -artifacts-dir "$KVLT_PROVISION_ARTIFACTS_DIR"
fi

CONFIG_PATH="${2:-${KVLT_CONFIG:-}}"
if [ "$#" -gt 2 ] || [ -z "$CONFIG_PATH" ] || [[ "$CONFIG_PATH" != /* ]] || [ ! -f "$CONFIG_PATH" ]; then
	echo "serve requires an existing absolute configuration path" >&2
	exit 2
fi
echo "building service and operations CLI..."
mkdir -p "$SCRIPT_DIR/bin"
go build -trimpath -o bin/key-vault ./cmd/key-vault
go build -trimpath -o bin/kvltctl ./cmd/kvltctl

echo "starting key-vault from explicit configuration: $CONFIG_PATH"
exec "$SCRIPT_DIR/bin/key-vault" -config "$CONFIG_PATH"
