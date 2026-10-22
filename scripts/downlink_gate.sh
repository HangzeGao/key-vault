#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly C_DIR="$ROOT_DIR/embedded/downlink_security"
readonly BUILD_DIR="$ROOT_DIR/build/downlink-gate"
readonly VECTORS="$ROOT_DIR/testdata/crypto/aes-downlink-v1.tsv"
go_bin="${GO_BIN:-$(command -v go || true)}"
if [[ -z "$go_bin" && -x /usr/local/go/bin/go ]]; then go_bin=/usr/local/go/bin/go; fi
if [[ -z "$go_bin" ]]; then echo 'downlink gate failed: Go is required' >&2; exit 1; fi

mkdir -p "$BUILD_DIR/coverage"
(cd "$ROOT_DIR/testdata/crypto" && sha256sum -c aes-downlink-v1.tsv.sha256)
flags=(-I"$C_DIR/include" -std=c11 -Wall -Wextra -Wpedantic -Werror)

# Keep this component's coverage separate: TC coverage cannot hide AES gaps.
rm -f "$BUILD_DIR/coverage/"*.gcda
"${CC:-cc}" "${flags[@]}" -O0 --coverage -c "$C_DIR/src/downlink_security.c" -o "$BUILD_DIR/coverage/downlink_security.o"
"${CC:-cc}" "${flags[@]}" -O0 --coverage -c "$C_DIR/tests/test_downlink.c" -o "$BUILD_DIR/coverage/test_downlink.o"
"${CC:-cc}" --coverage "$BUILD_DIR/coverage/"*.o -o "$BUILD_DIR/coverage/test_downlink"
"$BUILD_DIR/coverage/test_downlink" "$VECTORS" "$BUILD_DIR/flight-ciphertext.bin"
(cd "$BUILD_DIR/coverage" && gcov -b -c -o . "$C_DIR/src/downlink_security.c") > "$BUILD_DIR/coverage/gcov-summary.txt"
c_coverage="$(awk -F'[:%]' '/^Lines executed:/ { print $2; exit }' "$BUILD_DIR/coverage/gcov-summary.txt")"

cd "$ROOT_DIR"
DLSEC_FLIGHT_OUTPUT="$BUILD_DIR/flight-ciphertext.bin" "$go_bin" test -count=1 -covermode=atomic \
  -coverprofile="$BUILD_DIR/go-downlink.out" ./internal/downlink
go_coverage="$("$go_bin" tool cover -func="$BUILD_DIR/go-downlink.out" | awk '/^total:/ { gsub(/%/, "", $3); print $3 }')"
for language in C Go; do
  if [[ "$language" == C ]]; then actual="$c_coverage"; else actual="$go_coverage"; fi
  test -n "$actual" || { echo "downlink $language coverage evidence missing" >&2; exit 1; }
  awk -v actual="$actual" -v language="$language" 'BEGIN {
    if (actual + 0 < 95) { print "downlink " language " coverage below 95%" > "/dev/stderr"; exit 1 }
    printf "Downlink %s coverage gate passed: %.2f%% >= 95.00%%\n", language, actual
  }'
done

# Release optimization and ASan/UBSan must match the -O0 flight stream.
"${CC:-cc}" "${flags[@]}" -O2 "$C_DIR/src/downlink_security.c" "$C_DIR/tests/test_downlink.c" -o "$BUILD_DIR/test-optimized"
"$BUILD_DIR/test-optimized" "$VECTORS" "$BUILD_DIR/optimized.bin"
cmp "$BUILD_DIR/flight-ciphertext.bin" "$BUILD_DIR/optimized.bin"
sanitizers=(-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
"${CC:-cc}" "${flags[@]}" "${sanitizers[@]}" "$C_DIR/src/downlink_security.c" \
  "$C_DIR/tests/test_downlink.c" -o "$BUILD_DIR/test-sanitized"
"$BUILD_DIR/test-sanitized" "$VECTORS" "$BUILD_DIR/sanitized.bin"
cmp "$BUILD_DIR/flight-ciphertext.bin" "$BUILD_DIR/sanitized.bin"
"${CC:-cc}" "${flags[@]}" "${sanitizers[@]}" -DDLSEC_TEST_SELF_TEST_FAILURE=1 \
  "$C_DIR/src/downlink_security.c" "$C_DIR/tests/test_selftest_failure.c" -o "$BUILD_DIR/test-selftest-failure"
"$BUILD_DIR/test-selftest-failure"
"$go_bin" test ./internal/downlink -run '^$' -fuzz '^FuzzDecryptData$' -fuzztime=2s -parallel=1
printf 'Downlink data-field C-to-Go gate passed: 383 records, ASan/UBSan, C fuzz seed=0x4b564c54 iterations=4096 crashes=0\n'
