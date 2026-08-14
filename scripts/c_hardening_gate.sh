#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly C_DIR="$ROOT_DIR/embedded/tc_security"
readonly BUILD_DIR="$C_DIR/build/hardening"
readonly FUZZ_SEED="0x4b564c54"
readonly FUZZ_ITERATIONS="4096"
readonly SANITIZERS="address,undefined"
readonly SOURCES=(
  src/tc_security.c
  src/tc_security_nvm.c
  src/selftest.c
  src/sm4.c
  src/hctr.c
  src/gcm.c
  src/kdf.c
)

rm -rf -- "$BUILD_DIR"
mkdir -p -- "$BUILD_DIR"

common_flags=(
  -I"$C_DIR/include" -I"$C_DIR/src"
  -std=c11 -O1 -g -Wall -Wextra -Wpedantic -Werror
  -fno-omit-frame-pointer "-fsanitize=$SANITIZERS"
)
source_paths=()
for source in "${SOURCES[@]}"; do source_paths+=("$C_DIR/$source"); done

"${CC:-cc}" "${common_flags[@]}" "${source_paths[@]}" \
  "$C_DIR/tests/test_tc_security.c" -o "$BUILD_DIR/test_tc_security"
"$BUILD_DIR/test_tc_security" \
  "$ROOT_DIR/testdata/ccsds_tc_sm4_hctr.txt" \
  "$ROOT_DIR/testdata/ccsds_tc_sm4_gcm_recovery.txt"

"${CC:-cc}" "${common_flags[@]}" "${source_paths[@]}" \
  "$C_DIR/tests/test_fuzz_smoke.c" -o "$BUILD_DIR/test_fuzz_smoke"
"$BUILD_DIR/test_fuzz_smoke" \
  "$ROOT_DIR/testdata/ccsds_tc_sm4_hctr.txt" "$FUZZ_SEED" "$FUZZ_ITERATIONS"

printf 'C hardening gate passed: ASan/UBSan, seed=%s, iterations=%s, crashes=0\n' \
  "$FUZZ_SEED" "$FUZZ_ITERATIONS"
