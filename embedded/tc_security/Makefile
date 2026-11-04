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
TC_SOURCES := src/tc_security.c src/selftest.c src/sm4.c src/hctr.c src/gcm.c src/kdf.c
NVM_DIR := adapters/nvm
NVM_SOURCE := $(NVM_DIR)/tc_security_nvm.c
NVM_HEADER := $(NVM_DIR)/tc_security_nvm.h
ASM_SOURCES :=
ifeq ($(ARMV7_NEON),1)
CPPFLAGS += -DTCSEC_HAVE_ARMV7_NEON_ASM=1
ASM_SOURCES += src/sm4_armv7_neon.S
endif
CORE_HEADERS := include/tc_security.h include/tc_security_kdf.h src/tc_security_internal.h src/selftest.h src/sm4.h src/hctr.h src/gcm.h
CORE_LIB := $(BUILD_DIR)/libtc_security.a
NVM_LIB := $(BUILD_DIR)/libtc_security_nvm.a
CORE_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(TC_SOURCES)) \
                $(patsubst src/%.S,$(BUILD_DIR)/%.o,$(ASM_SOURCES))

.PHONY: all core nvm-adapter test clean print-backend

all: $(TEST_BIN)

core: $(CORE_LIB)

nvm-adapter: $(NVM_LIB)

$(BUILD_DIR)/%.o: src/%.c $(CORE_HEADERS)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: src/%.S
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/tc_security_nvm.o: $(NVM_SOURCE) $(NVM_HEADER) include/tc_security.h src/tc_security_internal.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(CORE_LIB): $(CORE_OBJECTS)
	$(AR) rcs $@ $^

$(NVM_LIB): $(BUILD_DIR)/tc_security_nvm.o
	$(AR) rcs $@ $^

$(TEST_BIN): tests/test_tc_security.c $(CORE_LIB) $(NVM_LIB) $(NVM_HEADER)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -I$(NVM_DIR) $(CFLAGS) \
		tests/test_tc_security.c $(NVM_LIB) $(CORE_LIB) $(LDFLAGS) -o $@

$(DISPATCH_TEST_BIN): src/sm4.c src/sm4.h tests/test_sm4_dispatch.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DTCSEC_HAVE_ARMV7_NEON_ASM=1 \
		-DTCSEC_TEST_ARMV7_CAPABILITY=1 src/sm4.c tests/test_sm4_dispatch.c $(LDFLAGS) -o $(DISPATCH_TEST_BIN)

$(SELFTEST_FAILURE_BIN): $(TC_SOURCES) $(CORE_HEADERS) tests/test_selftest_failure.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DTCSEC_TEST_SELF_TEST_FAILURE=1 \
		$(TC_SOURCES) \
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
