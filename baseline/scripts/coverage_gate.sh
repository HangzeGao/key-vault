#!/usr/bin/env bash
set -euo pipefail

readonly REQUIRED_COVERAGE="95.0"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly C_DIR="$ROOT_DIR/embedded/tc_security"
readonly COVERAGE_DIR="$C_DIR/build/coverage"

go_bin="$(command -v go || true)"
if [[ -z "$go_bin" && -x /usr/local/go/bin/go ]]; then
  go_bin=/usr/local/go/bin/go
fi
if [[ -z "$go_bin" ]]; then
  echo "coverage gate failed: Go toolchain not found" >&2
  exit 1
fi
readonly GO_BIN="$go_bin"

assert_coverage() {
  local name="$1"
  local actual="$2"
  awk -v name="$name" -v actual="$actual" -v required="$REQUIRED_COVERAGE" 'BEGIN {
    if ((actual + 0) < (required + 0)) {
      printf "%s coverage gate failed: %.2f%% < %.2f%%\n", name, actual, required > "/dev/stderr"
      exit 1
    }
    printf "%s coverage gate passed: %.2f%% >= %.2f%%\n", name, actual, required
  }'
}

rm -rf -- "$C_DIR/build"
mkdir -p -- "$COVERAGE_DIR"

readonly C_SOURCES=(
  src/tc_security.c
  src/tc_security_nvm.c
  src/sm4.c
  src/hctr.c
  src/gcm.c
  src/kdf.c
  tests/test_tc_security.c
)

for source in "${C_SOURCES[@]}"; do
  object="$COVERAGE_DIR/$(basename "${source%.c}").o"
  "${CC:-cc}" -I"$C_DIR/include" -I"$C_DIR/src" \
    -std=c11 -O0 -Wall -Wextra -Wpedantic -Werror --coverage \
    -c "$C_DIR/$source" -o "$object"
done

"${CC:-cc}" --coverage "$COVERAGE_DIR"/*.o -o "$COVERAGE_DIR/test_tc_security"
"$COVERAGE_DIR/test_tc_security" \
  "$ROOT_DIR/testdata/ccsds_tc_sm4_hctr.txt" \
  "$ROOT_DIR/testdata/ccsds_tc_sm4_gcm_recovery.txt"

readonly GCOV_OUTPUT="$COVERAGE_DIR/gcov-summary.txt"
(
  cd "$COVERAGE_DIR"
  gcov -b -c -o . \
    "$C_DIR/src/tc_security.c" "$C_DIR/src/sm4.c" "$C_DIR/src/hctr.c" \
    "$C_DIR/src/gcm.c" "$C_DIR/src/kdf.c" "$C_DIR/src/tc_security_nvm.c"
) | tee "$GCOV_OUTPUT"

c_coverage="$(awk -F'[:%]' '/^Lines executed:/ { value=$2 } END { print value }' "$GCOV_OUTPUT")"
if [[ -z "$c_coverage" ]]; then
  echo "C coverage gate failed: gcov did not report an aggregate line percentage" >&2
  exit 1
fi
assert_coverage "Flight C line" "$c_coverage"

readonly GO_PACKAGES=(
  ./internal/protocol/ccsds
  ./internal/securitystate
  ./internal/crypto/aead
  ./internal/crypto/suite
  ./internal/domain/policy
)
go_coverpkg="$(IFS=,; echo "${GO_PACKAGES[*]}")"
readonly GO_PROFILE="$COVERAGE_DIR/go-tc.out"

(
  cd "$ROOT_DIR"
  "$GO_BIN" test ./cmd/key-vault ./cmd/ccsds-provision
  "$GO_BIN" test -count=1 -covermode=atomic -coverpkg="$go_coverpkg" \
    -coverprofile="$GO_PROFILE" "${GO_PACKAGES[@]}"
)

go_coverage="$(cd "$ROOT_DIR" && "$GO_BIN" tool cover -func="$GO_PROFILE" | awk '/^total:/ { gsub(/%/, "", $3); print $3 }')"
if [[ -z "$go_coverage" ]]; then
  echo "Ground Go coverage gate failed: go tool cover did not report a total" >&2
  exit 1
fi
assert_coverage "Ground TC Go statement" "$go_coverage"
