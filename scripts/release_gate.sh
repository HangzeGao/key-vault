#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly EVIDENCE_DIR="$ROOT_DIR/build/release"

go_bin="$(command -v go || true)"
if [[ -z "$go_bin" && -x /usr/local/go/bin/go ]]; then go_bin=/usr/local/go/bin/go; fi
if [[ -z "$go_bin" ]]; then echo "release gate failed: Go toolchain not found" >&2; exit 1; fi
cd "$ROOT_DIR"
bash -n start.sh
"$go_bin" run ./scripts/tools/flight-manual-header --check
GO_BIN="$go_bin" bash scripts/go_security_gate.sh
GO_BIN="$go_bin" bash scripts/c_hardening_gate.sh
GO_BIN="$go_bin" bash scripts/tc_process_gate.sh
tc_process_count="$(awk '/"scenario_count":/ {gsub(/,/,"",$2); print $2}' "$ROOT_DIR/build/tc-process-gate/optimized-report.json")"
if [[ ! "$tc_process_count" =~ ^[1-9][0-9]*$ ]]; then echo 'release gate failed: TC scenario count missing' >&2; exit 1; fi

GO_BIN="$go_bin" bash scripts/external_vector_gate.sh

if ! downlink_output="$(GO_BIN="$go_bin" bash scripts/downlink_gate.sh)"; then
  printf '%s\n' "$downlink_output"
  exit 1
fi
printf '%s\n' "$downlink_output"
downlink_c_coverage="$(printf '%s\n' "$downlink_output" | awk '/Downlink C coverage gate passed/ {gsub(/%/,"",$6); print $6}')"
downlink_go_coverage="$(printf '%s\n' "$downlink_output" | awk '/Downlink Go coverage gate passed/ {gsub(/%/,"",$6); print $6}')"
if [[ -z "$downlink_c_coverage" || -z "$downlink_go_coverage" ]]; then echo 'release gate failed: downlink coverage evidence missing' >&2; exit 1; fi

GO_BIN="$go_bin" bash scripts/armv7_gate.sh

coverage_output="$(bash scripts/coverage_gate.sh)"
printf '%s\n' "$coverage_output"
c_coverage="$(printf '%s\n' "$coverage_output" | awk '/Flight C line coverage gate passed/ {gsub(/%/,"",$7); print $7}')"
go_coverage="$(printf '%s\n' "$coverage_output" | awk '/Ground TC Go statement coverage gate passed/ {gsub(/%/,"",$8); print $8}')"
access_coverage="$(printf '%s\n' "$coverage_output" | awk '/Ground access Go statement coverage gate passed/ {gsub(/%/,"",$8); print $8}')"
if [[ -z "$c_coverage" || -z "$go_coverage" || -z "$access_coverage" ]]; then echo "release gate failed: coverage evidence missing" >&2; exit 1; fi

mkdir -p "$EVIDENCE_DIR"
GO_BIN="$go_bin" bash scripts/flight_package_gate.sh
"$go_bin" build -o "$EVIDENCE_DIR/key-vault-gate" ./cmd/key-vault
if ! diff -u <("$go_bin" list ./...) <("$go_bin" list -tags downlink ./...); then
  echo "release gate failed: obsolete downlink build tag changes package set" >&2
  exit 1
fi

commit=unavailable
dirty=true
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  commit="$(git rev-parse HEAD)"
  dirty=false
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then dirty=true; fi
fi
source_manifest_hash="$({
  find cmd examples internal scripts embedded/tc_security/src embedded/tc_security/include embedded/tc_security/tools \
    embedded/tc_security/tests embedded/downlink_security/src embedded/downlink_security/include \
    embedded/downlink_security/tests -type f -print
  printf '%s\n' Makefile embedded/tc_security/Makefile embedded/downlink_security/Makefile start.sh go.mod go.sum
} | LC_ALL=C sort | xargs sha256sum | sha256sum | awk '{print $1}')"
ordinary_hash="$(sha256sum testdata/ccsds_tc_sm4_hctr.txt | awk '{print $1}')"
recovery_hash="$(sha256sum testdata/ccsds_tc_sm4_gcm_recovery.txt | awk '{print $1}')"
external_vector_hash="$(sha256sum testdata/crypto/cryptography-sm4-v1.tsv | awk '{print $1}')"
external_generator_hash="$(sha256sum scripts/oracle/cryptography_vector_generator.py | awk '{print $1}')"
cat > "$EVIDENCE_DIR/release-evidence.json" <<EOF
{
  "format_version": 11,
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_commit": "$commit",
  "dirty_worktree": $dirty,
  "source_manifest_sha256": "$source_manifest_hash",
  "flight_public_header_sha256": "$(sha256sum embedded/tc_security/include/tc_security.h | awk '{print $1}')",
  "flight_interface_manual_md_sha256": "$(sha256sum docs/FLIGHT_INTERFACE_MANUAL.md | awk '{print $1}')",
  "flight_interface_manual_docx_sha256": "$(sha256sum docs/星务端密码模块接口手册.docx | awk '{print $1}')",
  "flight_manual_header_reference": "passed",
  "go_toolchain": "$("$go_bin" env GOVERSION)",
  "c_compiler": "$("${CC:-cc}" --version | head -1)",
  "go_race": "passed",
  "govulncheck_version": "v1.7.0",
  "reachable_go_vulnerabilities": 0,
  "c_sanitizers": "address,undefined",
  "c_smoke_fuzz_seed": "0x4b564c54",
  "c_smoke_fuzz_iterations": 4096,
  "c_smoke_fuzz_crashes": 0,
  "flight_c_line_coverage": $c_coverage,
  "ground_tc_go_statement_coverage": $go_coverage,
  "ground_access_go_statement_coverage": $access_coverage,
  "ordinary_vector_sha256": "$ordinary_hash",
  "recovery_vector_sha256": "$recovery_hash",
  "external_vector_generator": "pyca/cryptography 49.0.0 (OpenSSL 4.0.1) + RFC 8998 Appendix A.1",
  "external_vector_generator_sha256": "$external_generator_hash",
  "external_vector_sha256": "$external_vector_hash",
  "external_vector_records": 28,
  "rfc8998_sm4_gcm": "passed",
  "external_sm4_block_cmac_gcm_hctr_kdf": "passed",
  "api_to_flight_vector": "passed",
  "current_tc_http_sqlite_c_process_recovery": "passed",
  "tc_process_scenario_count": $tc_process_count,
  "tc_process_scenario_executions": $((tc_process_count * 2)),
  "tc_process_scenario_failures": 0,
  "tc_process_scenario_skips": 0,
  "tc_process_scenario_manifest_sha256": "$(sha256sum testdata/tc-process-scenarios.json | awk '{print $1}')",
  "tc_process_optimized_report_sha256": "$(sha256sum build/tc-process-gate/optimized-report.json | awk '{print $1}')",
  "tc_process_sanitized_report_sha256": "$(sha256sum build/tc-process-gate/sanitized-report.json | awk '{print $1}')",
  "tc_process_scope": "host HTTP/SQLite/C process with test key source, synthetic Next policy and file-backed persistence; physical TPM/NVM and mission rules excluded",
  "downlink_data_field_c_to_go": "passed",
  "downlink_c_line_coverage": $downlink_c_coverage,
  "downlink_go_statement_coverage": $downlink_go_coverage,
  "downlink_vector_records": 383,
  "downlink_vector_sha256": "$(sha256sum testdata/crypto/aes-downlink-v1.tsv | awk '{print $1}')",
  "downlink_generator_sha256": "$(sha256sum scripts/oracle/aes_downlink_vectors.py | awk '{print $1}')",
  "downlink_oracle": "pyca/cryptography 50.0.2 (OpenSSL 4.0.3) + NIST SP 800-38A F.1.5",
  "downlink_c_sanitizers": "address,undefined",
  "downlink_c_smoke_fuzz_seed": "0x4b564c54",
  "downlink_c_smoke_fuzz_iterations": 4096,
  "downlink_c_smoke_fuzz_crashes": 0,
  "downlink_go_smoke_fuzz_seconds": 2,
  "downlink_armv7_c_to_go": "passed",
  "armv7_cross_compile": "passed",
  "armv7_qemu_neon": "passed",
  "go_x86_armv7_differential_records": 256,
  "operations_cli_test": "passed",
  "flight_public_header_archive_link": "passed",
  "browser_asset_chain": "absent"
}
EOF
printf 'Release evidence: %s\n' "$EVIDENCE_DIR/release-evidence.json"
