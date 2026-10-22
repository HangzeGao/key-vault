#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly REQUIRED_GO_VERSION="go1.26.10"
readonly GOVULNCHECK_VERSION="v1.7.0"

go_bin="${GO_BIN:-$(command -v go || true)}"
if [[ -z "$go_bin" && -x /usr/local/go/bin/go ]]; then go_bin=/usr/local/go/bin/go; fi
if [[ -z "$go_bin" ]]; then
  echo "Go security gate failed: Go toolchain not found" >&2
  exit 1
fi

cd "$ROOT_DIR"
actual_version="$("$go_bin" env GOVERSION)"
if [[ "$actual_version" != "$REQUIRED_GO_VERSION" ]]; then
  echo "Go security gate failed: required $REQUIRED_GO_VERSION, found $actual_version" >&2
  exit 1
fi

CGO_ENABLED=1 "$go_bin" test -race ./...
"$go_bin" run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" ./...
printf 'Go security gate passed: %s, race, govulncheck %s\n' \
  "$actual_version" "$GOVULNCHECK_VERSION"
