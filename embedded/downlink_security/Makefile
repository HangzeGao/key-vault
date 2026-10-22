CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS ?= -Iinclude
BUILD_DIR := build
SOURCES := src/downlink_security.c
HEADERS := include/downlink_security.h

.PHONY: all test clean
all: $(BUILD_DIR)/test_downlink $(BUILD_DIR)/test_selftest_failure

$(BUILD_DIR)/test_downlink: $(SOURCES) $(HEADERS) tests/test_downlink.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) tests/test_downlink.c $(LDFLAGS) -o $@

$(BUILD_DIR)/test_selftest_failure: $(SOURCES) $(HEADERS) tests/test_selftest_failure.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DDLSEC_TEST_SELF_TEST_FAILURE=1 $(SOURCES) tests/test_selftest_failure.c $(LDFLAGS) -o $@

test: all
	$(BUILD_DIR)/test_downlink ../../testdata/crypto/aes-downlink-v1.tsv
	$(BUILD_DIR)/test_selftest_failure

clean:
	rm -rf $(BUILD_DIR)
