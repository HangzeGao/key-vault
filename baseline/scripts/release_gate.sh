#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly EVIDENCE_DIR="$ROOT_DIR/build/release"

go_bin="$(command -v go || true)"
if [[ -z "$go_bin" && -x /usr/local/go/bin/go ]]; then go_bin=/usr/local/go/bin/go; fi
if [[ -z "$go_bin" ]]; then echo "release gate failed: Go toolchain not found" >&2; exit 1; fi
cd "$ROOT_DIR"
"$go_bin" test ./...
"$go_bin" test -count=1 -run '^TestTCDataPlaneAPIProducesFlightAcceptedVector$' ./internal/api/ccsds
"$go_bin" test -count=1 -run '^TestDownlinkBatchToAuthenticatedHTTPPlaintext$' ./internal/api/ccsds

GO_BIN="$go_bin" bash scripts/armv7_gate.sh

coverage_output="$(bash scripts/coverage_gate.sh)"
printf '%s\n' "$coverage_output"
c_coverage="$(printf '%s\n' "$coverage_output" | awk '/Flight C line coverage gate passed/ {gsub(/%/,"",$7); print $7}')"
go_coverage="$(printf '%s\n' "$coverage_output" | awk '/Ground TC Go statement coverage gate passed/ {gsub(/%/,"",$8); print $8}')"
if [[ -z "$c_coverage" || -z "$go_coverage" ]]; then echo "release gate failed: coverage evidence missing" >&2; exit 1; fi

mkdir -p "$EVIDENCE_DIR"
commit=unavailable
dirty=true
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  commit="$(git rev-parse HEAD)"
  dirty=false
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then dirty=true; fi
fi
source_manifest_hash="$({
  find cmd internal scripts embedded/tc_security/src embedded/tc_security/include \
    embedded/tc_security/tests -type f -print
  printf '%s\n' Makefile go.mod go.sum
} | LC_ALL=C sort | xargs sha256sum | sha256sum | awk '{print $1}')"
ordinary_hash="$(sha256sum testdata/ccsds_tc_sm4_hctr.txt | awk '{print $1}')"
recovery_hash="$(sha256sum testdata/ccsds_tc_sm4_gcm_recovery.txt | awk '{print $1}')"
cat > "$EVIDENCE_DIR/release-evidence.json" <<EOF
{
  "format_version": 3,
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_commit": "$commit",
  "dirty_worktree": $dirty,
  "source_manifest_sha256": "$source_manifest_hash",
  "flight_c_line_coverage": $c_coverage,
  "ground_tc_go_statement_coverage": $go_coverage,
  "ordinary_vector_sha256": "$ordinary_hash",
  "recovery_vector_sha256": "$recovery_hash",
  "api_to_flight_vector": "passed",
  "downlink_batch_to_http_plaintext": "passed",
  "armv7_cross_compile": "passed",
  "armv7_qemu_neon": "passed",
  "go_x86_armv7_differential_records": 256,
  "operations_cli_test": "passed",
  "browser_asset_chain": "absent"
}
EOF
printf 'Release evidence: %s\n' "$EVIDENCE_DIR/release-evidence.json"
