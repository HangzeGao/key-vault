CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS ?= -Iinclude -Isrc

BUILD_DIR := build
TEST_BIN := $(BUILD_DIR)/test_tc_security
SOURCES := src/tc_security.c src/tc_security_nvm.c src/sm4.c src/hctr.c src/gcm.c src/kdf.c tests/test_tc_security.c

.PHONY: all test clean

all: $(TEST_BIN)

$(TEST_BIN): $(SOURCES) include/tc_security.h include/tc_security_nvm.h include/tc_security_kdf.h src/tc_security_internal.h src/sm4.h src/hctr.h src/gcm.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $(TEST_BIN)

test: $(TEST_BIN)
	$(TEST_BIN) ../../testdata/ccsds_tc_sm4_hctr.txt \
		../../testdata/ccsds_tc_sm4_gcm_recovery.txt

clean:
	rm -rf $(BUILD_DIR)
