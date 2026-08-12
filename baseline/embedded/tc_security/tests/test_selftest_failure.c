#include "tc_security.h"

#include <string.h>

static int validate(void *user, const uint8_t header[TCSEC_PRIMARY_HEADER_LENGTH],
                    const uint8_t *plaintext, size_t length) {
    (void)user; (void)header; (void)plaintext; (void)length;
    return 1;
}

static tcsec_commit_result_t commit(void *user, const tcsec_commit_t *value) {
    (void)user; (void)value;
    return TCSEC_COMMIT_NEW;
}

static uint64_t now(void *user) {
    (void)user;
    return 1u;
}

int main(void) {
    tcsec_config_t config;
    tcsec_context_t context;
    tcsec_runtime_status_t status;
    tcsec_callbacks_t callbacks = {validate, commit, now, NULL};
    memset(&config, 0, sizeof(config));
    memset(config.profile_digest, 0x5au, sizeof(config.profile_digest));
    config.ordinary.spacecraft_id = 1u;
    config.ordinary.suite = TCSEC_SUITE_SM4_HCTR;
    memset(config.ordinary.operational_root, 1, TCSEC_ROOT_KEY_LENGTH);
    config.ordinary.operational_root_length = TCSEC_ROOT_KEY_LENGTH;
    config.ordinary.root_version = 1u;
    config.ordinary.current_epoch = 1u;
    config.ordinary.current_spi = 1u;
    memset(config.ordinary.nonce_prefix, 2, TCSEC_NONCE_PREFIX_LENGTH);
    config.recovery.suite = TCSEC_SUITE_SM4_GCM;
    memset(config.recovery.recovery_root, 3, TCSEC_ROOT_KEY_LENGTH);
    config.recovery.recovery_root_length = TCSEC_ROOT_KEY_LENGTH;
    config.recovery.root_version = 1u;
    config.recovery.spi = 3u;
    memset(config.recovery.nonce_prefix, 4, TCSEC_NONCE_PREFIX_LENGTH);
    if (tcsec_init(&context, &config, &callbacks) != TCSEC_SELF_TEST_FAILED ||
        tcsec_get_runtime_status(&context, &status) != TCSEC_SELF_TEST_FAILED ||
        status.self_test != TCSEC_SELF_TEST_LOCKED ||
        tcsec_reset(&context, &config) != TCSEC_SELF_TEST_FAILED)
        return 1;
    return 0;
}
