CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS ?= -Iinclude -Isrc
ARMV7_NEON ?= auto

TARGET_MACHINE := $(shell $(CC) -dumpmachine 2>/dev/null)
TARGET_ARM_ARCH := $(shell printf '' | $(CC) $(CPPFLAGS) $(CFLAGS) -dM -E - 2>/dev/null | awk '/^#define __ARM_ARCH / { print $$3 }')
ifeq ($(ARMV7_NEON),auto)
ifneq ($(filter 7,$(TARGET_ARM_ARCH)),)
ARMV7_NEON := 1
else
ARMV7_NEON := 0
endif
endif

BUILD_DIR := build
TEST_BIN := $(BUILD_DIR)/test_tc_security
DISPATCH_TEST_BIN := $(BUILD_DIR)/test_sm4_dispatch
SELFTEST_FAILURE_BIN := $(BUILD_DIR)/test_selftest_failure
EXTERNAL_VECTOR_TEST_BIN := $(BUILD_DIR)/test_external_vectors
TC_SOURCES := src/tc_security.c src/next_validation.c src/selftest.c src/sm4.c src/hctr.c src/gcm.c src/kdf.c
TEST_POLICY := tests/test_next_policy.c
ASM_SOURCES :=
ifeq ($(ARMV7_NEON),1)
CPPFLAGS += -DTCSEC_HAVE_ARMV7_NEON_ASM=1
ASM_SOURCES += src/sm4_armv7_neon.S
endif
CORE_HEADERS := include/tc_security.h include/tc_security_kdf.h src/context_private.h src/next_validation.h src/selftest.h src/sm4.h src/hctr.h src/gcm.h
CORE_LIB := $(BUILD_DIR)/libtc_security.a
CORE_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(TC_SOURCES)) \
                $(patsubst src/%.S,$(BUILD_DIR)/%.o,$(ASM_SOURCES))

.PHONY: all core test-binary test clean print-backend flight-package

all: core

test-binary: $(TEST_BIN)

core: $(CORE_LIB)

$(BUILD_DIR)/%.o: src/%.c $(CORE_HEADERS)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: src/%.S
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(CORE_LIB): $(CORE_OBJECTS)
	$(AR) rcs $@ $^

$(TEST_BIN): tests/test_tc_security.c tests/storage_quorum_model.h $(TEST_POLICY) $(CORE_LIB) tools/tc_security_diagnostics.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DTCSEC_TEST_NEXT_POLICY=1 \
		tests/test_tc_security.c $(TEST_POLICY) $(CORE_LIB) $(LDFLAGS) -o $@

$(DISPATCH_TEST_BIN): src/sm4.c src/sm4.h tests/test_sm4_dispatch.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DTCSEC_HAVE_ARMV7_NEON_ASM=1 \
		-DTCSEC_TEST_ARMV7_CAPABILITY=1 src/sm4.c tests/test_sm4_dispatch.c $(LDFLAGS) -o $(DISPATCH_TEST_BIN)

$(SELFTEST_FAILURE_BIN): $(TC_SOURCES) $(CORE_HEADERS) $(TEST_POLICY) tests/test_selftest_failure.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DTCSEC_TEST_SELF_TEST_FAILURE=1 -DTCSEC_TEST_NEXT_POLICY=1 \
		$(TC_SOURCES) $(TEST_POLICY) \
		tests/test_selftest_failure.c $(LDFLAGS) -o $(SELFTEST_FAILURE_BIN)

$(EXTERNAL_VECTOR_TEST_BIN): src/sm4.c src/hctr.c src/gcm.c src/kdf.c tests/test_external_vectors.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DTCSEC_TEST_CRYPTO_PRIMITIVES=1 \
		src/sm4.c src/hctr.c src/gcm.c src/kdf.c tests/test_external_vectors.c \
		$(LDFLAGS) -o $(EXTERNAL_VECTOR_TEST_BIN)

test: $(TEST_BIN) $(DISPATCH_TEST_BIN) $(SELFTEST_FAILURE_BIN) $(EXTERNAL_VECTOR_TEST_BIN)
	$(TEST_BIN) ../../testdata/ccsds_tc_sm4_hctr.txt \
		../../testdata/ccsds_tc_sm4_gcm_recovery.txt
	$(DISPATCH_TEST_BIN)
	$(SELFTEST_FAILURE_BIN)
	$(EXTERNAL_VECTOR_TEST_BIN) ../../testdata/crypto/cryptography-sm4-v1.tsv

clean:
	rm -rf $(BUILD_DIR)

print-backend:
	@printf 'SM4 build backend: %s (target %s, ARM arch %s)\n' \
		"$(if $(filter 1,$(ARMV7_NEON)),armv7-neon+software,software)" \
		"$(TARGET_MACHINE)" "$(if $(TARGET_ARM_ARCH),$(TARGET_ARM_ARCH),n/a)"

# The delivered archive contains the reviewed mission policy. Internal headers
# and test policies are not part of the flight-software delivery interface.
flight-package:
	@test -n "$(MISSION_POLICY)" -a -f "$(MISSION_POLICY)" || { echo 'MISSION_POLICY must name the approved mission policy source' >&2; exit 1; }
	@case "$(abspath $(MISSION_POLICY))" in */tests/*) echo 'test policy cannot be packaged for flight' >&2; exit 1;; esac
	$(MAKE) core BUILD_DIR=$(BUILD_DIR)/flight-objects
	mkdir -p $(BUILD_DIR)/flight-package
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$(MISSION_POLICY)" -o $(BUILD_DIR)/flight-package/mission_policy.o
	cp $(BUILD_DIR)/flight-objects/libtc_security.a $(BUILD_DIR)/flight-package/libtc_security.a
	$(AR) rcs $(BUILD_DIR)/flight-package/libtc_security.a $(BUILD_DIR)/flight-package/mission_policy.o
	cp include/tc_security.h $(BUILD_DIR)/flight-package/tc_security.h
	printf 'target=%s\nflags=%s\n' "$(TARGET_MACHINE)" "$(CFLAGS)" > $(BUILD_DIR)/flight-package/build-info.txt
	$(CC) --version >> $(BUILD_DIR)/flight-package/build-info.txt
	cd $(BUILD_DIR)/flight-package && sha256sum tc_security.h libtc_security.a build-info.txt > SHA256SUMS
