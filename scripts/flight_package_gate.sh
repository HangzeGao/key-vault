#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly C_DIR="$ROOT_DIR/embedded/tc_security"
readonly WORK="$C_DIR/build/package-gate"
mkdir -p "$WORK"

if make -C "$C_DIR" flight-package MISSION_POLICY= >"$WORK/rejected.log" 2>&1; then
  echo 'package gate failed: missing mission policy accepted' >&2
  exit 1
fi
if make -C "$C_DIR" flight-package MISSION_POLICY=tests/test_next_policy.c >>"$WORK/rejected.log" 2>&1; then
  echo 'package gate failed: repository test policy accepted' >&2
  exit 1
fi

# TEST ONLY: deny-all policy checks archive completeness and the caller seam.
# This fixture is never a mission rule or a flight release artifact.
cat > "$WORK/policy_fixture.c" <<'EOF'
#include <stddef.h>
#include <stdint.h>
int tcsec_mission_next_command_allowed(uint8_t vcid, uint16_t apid,
                                      const uint8_t *body, size_t length) {
    (void)vcid; (void)apid; (void)body; (void)length;
    return 0;
}
EOF
make -C "$C_DIR" flight-package CC="${CC:-cc}" AR="${AR:-ar}" \
  BUILD_DIR="$WORK/objects" MISSION_POLICY="$WORK/policy_fixture.c"
readonly PACKAGE="$WORK/objects/flight-package"
cat > "$WORK/caller.c" <<'EOF'
#include "tc_security.h"
static tcsec_status_t load(void *user, tcsec_config_t *out) {
    (void)user; (void)out;
    return TCSEC_STORAGE_NOT_COMMISSIONED;
}
static tcsec_commit_result_t commit(void *user, const tcsec_commit_t *change) {
    (void)user; (void)change;
    return TCSEC_COMMIT_REJECTED;
}
int main(void) {
    tcsec_context_t object = {0};
    tcsec_runtime_status_t state;
    tcsec_result_t result;
    uint8_t frame[32] = {0}, output[32] = {0};
    const tcsec_callbacks_t callbacks = {.load_state=load, .commit_state=commit};
    return tcsec_init(&object, &callbacks) != TCSEC_STORAGE_NOT_COMMISSIONED ||
           tcsec_reset(&object) != TCSEC_NOT_INITIALIZED ||
           tcsec_get_runtime_status(&object, &state) != TCSEC_NOT_INITIALIZED ||
           tcsec_receive(&object, frame, sizeof(frame), output, sizeof(output), &result) !=
               TCSEC_NOT_INITIALIZED;
}
EOF
"${CC:-cc}" -std=c11 -Wall -Wextra -Wpedantic -Werror -I"$PACKAGE" \
  "$WORK/caller.c" "$PACKAGE/libtc_security.a" -o "$WORK/caller"
"$WORK/caller"
(cd "$PACKAGE" && sha256sum -c SHA256SUMS)

cat > "$WORK/private_member.c" <<'EOF'
#include "tc_security.h"
int main(void) { tcsec_context_t object = {0}; return object.current_key[0]; }
EOF
if "${CC:-cc}" -std=c11 -Werror -I"$PACKAGE" -c "$WORK/private_member.c" \
    -o "$WORK/private_member.o" >"$WORK/private-member.log" 2>&1; then
  echo 'package gate failed: caller can access private key members' >&2
  exit 1
fi
printf 'Flight package seam gate passed: public header, complete archive, opaque object\n'
