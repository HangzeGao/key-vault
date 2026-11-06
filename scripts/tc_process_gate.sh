#!/usr/bin/env bash
set -euo pipefail
readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly C_DIR="$ROOT_DIR/embedded/tc_security"
readonly WORK="$ROOT_DIR/build/tc-process-gate"
mkdir -p "$WORK"
cd "$ROOT_DIR"
# The process campaign runs against the same library sources twice. Test-only
# file storage and synthetic mission policy never enter the flight archive.
for variant in optimized sanitized; do
  flags=(-O2)
  if [[ "$variant" == sanitized ]]; then
    flags=(-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
  fi
  "${CC:-cc}" -std=c11 -Wall -Wextra -Wpedantic -Werror "${flags[@]}" \
    -DTCSEC_TEST_NEXT_POLICY=1 -I"$C_DIR/include" -I"$C_DIR/src" \
    "$C_DIR"/src/{tc_security,next_validation,selftest,sm4,gcm,kdf}.c \
    "$C_DIR/tests/test_next_policy.c" "$C_DIR/tests/tc_receive_runner.c" -o "$WORK/tc_receive_runner-$variant"
  TC_E2E_REQUIRED=1 TC_E2E_FLIGHT_RUNNER="$WORK/tc_receive_runner-$variant" \
    "${GO_BIN:-go}" test -count=1 -json \
    -run '^(TestTCDataPlaneAPIProducesFlightAcceptedVector|TestTCFlight.*)$' ./internal/api/ccsds \
    | tee "$WORK/$variant.jsonl"
  "${GO_BIN:-go}" run ./scripts/tools/tc-process-report --events "$WORK/$variant.jsonl" \
    --variant "$variant" --output "$WORK/$variant-report.json"
done
printf 'TC process gate passed: registered scenarios, HTTP, SQLite, C sessions, restart, commit interruption, Next and Recovery\n'
