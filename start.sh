#!/usr/bin/env bash
set -euo pipefail

export PATH="$PATH:/usr/local/go/bin"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-}"
if [ "$MODE" != "serve" ]; then
  echo "usage: bash start.sh serve /absolute/path/config.yaml" >&2
  exit 2
fi

cd "$SCRIPT_DIR"
if [ "$(go env GOVERSION)" != "go1.26.11" ]; then
  echo "Go 1.26.11 is required" >&2
  exit 2
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
