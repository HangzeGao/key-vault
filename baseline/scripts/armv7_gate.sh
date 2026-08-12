#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly C_DIR="$ROOT_DIR/embedded/tc_security"
readonly BUILD_DIR="$ROOT_DIR/build/armv7-gate"
readonly VECTORS="$BUILD_DIR/differential.txt"

cc_arm="${ARMV7_CC:-$(command -v arm-linux-gnueabihf-gcc || true)}"
qemu_arm="${QEMU_ARM:-$(command -v qemu-arm || true)}"
go_bin="${GO_BIN:-$(command -v go || true)}"
if [[ -z "$cc_arm" || ! -x "$cc_arm" || -z "$qemu_arm" || ! -x "$qemu_arm" || -z "$go_bin" ]]; then
  echo "ARMv7 gate failed: ARMV7_CC, QEMU_ARM, and Go are required" >&2
  exit 1
fi
sysroot="${ARMV7_SYSROOT:-$($cc_arm --print-sysroot)}"
if [[ ! -d "$sysroot" ]]; then echo "ARMv7 gate failed: sysroot not found: $sysroot" >&2; exit 1; fi
toolchain_root="${ARMV7_TOOLCHAIN_ROOT:-}"
sysroot_flag=()
arm_cflags='-std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -march=armv7-a -mfpu=neon -mfloat-abi=hard'

rm -rf -- "$BUILD_DIR"
mkdir -p -- "$BUILD_DIR"
cd "$ROOT_DIR"
"$go_bin" run ./scripts/tools/crypto-diff-vectors -output "$VECTORS" -cases 128

readonly COMMON=(src/sm4.c src/hctr.c src/kdf.c tests/test_differential.c)
(
  cd "$C_DIR"
  "${CC:-cc}" -Iinclude -Isrc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror \
    "${COMMON[@]}" -o "$BUILD_DIR/diff-x86"
  "$BUILD_DIR/diff-x86" "$VECTORS" | tee "$BUILD_DIR/x86-result.txt"

  if [[ -n "$toolchain_root" ]]; then
    export PATH="$toolchain_root/usr/bin:$PATH"
    export LD_LIBRARY_PATH="$toolchain_root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export COMPILER_PATH="$toolchain_root/usr/lib/gcc-cross/arm-linux-gnueabihf/11:$toolchain_root/usr/lib/arm-linux-gnueabihf"
    export LIBRARY_PATH="$toolchain_root/usr/lib/gcc-cross/arm-linux-gnueabihf/11:$toolchain_root/usr/lib/arm-linux-gnueabihf:$toolchain_root/lib/arm-linux-gnueabihf"
    sysroot_flag=("--sysroot=$toolchain_root")
    arm_cflags="--sysroot=$toolchain_root $arm_cflags"
  fi

  make clean
  make CC="$cc_arm" ARMV7_NEON=1 \
    CFLAGS="$arm_cflags" all
  "$qemu_arm" -L "$sysroot" build/test_tc_security \
    "$ROOT_DIR/testdata/ccsds_tc_sm4_hctr.txt" "$ROOT_DIR/testdata/ccsds_tc_sm4_gcm_recovery.txt"
  "$cc_arm" "${sysroot_flag[@]}" -Iinclude -Isrc -DTCSEC_HAVE_ARMV7_NEON_ASM=1 -std=c11 -O2 \
    -Wall -Wextra -Wpedantic -Werror -march=armv7-a -mfpu=neon -mfloat-abi=hard \
    "${COMMON[@]}" src/sm4_armv7_neon.S -o "$BUILD_DIR/diff-armv7"
  "$qemu_arm" -L "$sysroot" "$BUILD_DIR/diff-armv7" "$VECTORS" | tee "$BUILD_DIR/armv7-result.txt"
)
grep -q 'backend=software cases=256' "$BUILD_DIR/x86-result.txt"
grep -q 'backend=armv7-neon cases=256' "$BUILD_DIR/armv7-result.txt"
printf 'ARMv7 cross/QEMU three-way differential gate passed: 256 records\n'
