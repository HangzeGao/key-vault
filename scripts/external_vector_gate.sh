#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly VECTOR_DIR="$ROOT_DIR/testdata/crypto"
readonly VECTOR_FILE="$VECTOR_DIR/cryptography-sm4-v1.tsv"
readonly CHECKSUM_FILE="$VECTOR_FILE.sha256"
readonly BUILD_DIR="$ROOT_DIR/build/external-vectors"
readonly TEST_BIN="$BUILD_DIR/test_external_vectors"

for tool in sha256sum "${CC:-cc}"; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'external vector gate failed: %s is required\n' "$tool" >&2
    exit 1
  }
done
test -s "$VECTOR_FILE" || { echo "external vector gate failed: vector file missing" >&2; exit 1; }
test -s "$CHECKSUM_FILE" || { echo "external vector gate failed: checksum missing" >&2; exit 1; }
(
  cd -- "$VECTOR_DIR"
  sha256sum -c "$(basename -- "$CHECKSUM_FILE")"
)

rm -rf -- "$BUILD_DIR"
mkdir -p -- "$BUILD_DIR"
"${CC:-cc}" -I"$ROOT_DIR/embedded/tc_security/include" \
  -I"$ROOT_DIR/embedded/tc_security/src" \
  -DTCSEC_TEST_CRYPTO_PRIMITIVES=1 -std=c11 -O2 \
  -Wall -Wextra -Wpedantic -Werror \
  "$ROOT_DIR/embedded/tc_security/src/sm4.c" \
  "$ROOT_DIR/embedded/tc_security/src/hctr.c" \
  "$ROOT_DIR/embedded/tc_security/src/gcm.c" \
  "$ROOT_DIR/embedded/tc_security/src/kdf.c" \
  "$ROOT_DIR/embedded/tc_security/tests/test_external_vectors.c" \
  -o "$TEST_BIN"
"$TEST_BIN" "$VECTOR_FILE"

go_bin="${GO_BIN:-$(command -v go || true)}"
if [[ -z "$go_bin" && -x /usr/local/go/bin/go ]]; then go_bin=/usr/local/go/bin/go; fi
if [[ -z "$go_bin" ]]; then echo "external vector gate failed: Go is required" >&2; exit 1; fi
(cd -- "$ROOT_DIR" && "$go_bin" test -count=1 -run '^TestExternalOpenSourceSM4Vectors$' ./internal/crypto/aead)
printf 'External pyca/cryptography and RFC vector gate passed\n'
