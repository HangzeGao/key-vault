#!/usr/bin/env bash
set -euo pipefail
readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly C_DIR="$ROOT_DIR/embedded/tc_security"
readonly WORK="$C_DIR/build/process-gate"
mkdir -p "$WORK"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
  -DTCSEC_TEST_NEXT_POLICY=1 -I"$C_DIR/include" -I"$C_DIR/src" \
  "$C_DIR"/src/{tc_security,next_validation,selftest,sm4,hctr,gcm,kdf}.c \
  "$C_DIR/tests/test_next_policy.c" "$C_DIR/tests/tc_receive_runner.c" -o "$WORK/tc_receive_runner"
cd "$ROOT_DIR"
TC_E2E_FLIGHT_RUNNER="$WORK/tc_receive_runner" "${GO_BIN:-go}" test -count=1 -v \
  -run '^TestTCDataPlaneAPIProducesFlightAcceptedVector$' ./internal/api/ccsds
printf 'TC process gate passed: HTTP, SQLite, C process, durable callback, restart, confirmation loss\n'
