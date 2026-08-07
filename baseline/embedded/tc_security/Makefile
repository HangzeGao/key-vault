CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS ?= -Iinclude -Isrc

BUILD_DIR := build
TEST_BIN := $(BUILD_DIR)/test_tc_security
SOURCES := src/tc_security.c src/aes256.c src/sm4.c src/gcm.c src/kdf.c tests/test_tc_security.c

.PHONY: all test clean

all: $(TEST_BIN)

$(TEST_BIN): $(SOURCES) include/tc_security.h include/tc_security_kdf.h src/aes256.h src/sm4.h src/gcm.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $(TEST_BIN)

test: $(TEST_BIN)
	$(TEST_BIN) ../../testdata/ccsds_tc_aes256_ctr.txt ../../testdata/ccsds_tc_sm4_ctr.txt \
		../../testdata/ccsds_tc_aes256_gcm_recovery.txt ../../testdata/ccsds_tc_sm4_gcm_recovery.txt

clean:
	rm -rf $(BUILD_DIR)
