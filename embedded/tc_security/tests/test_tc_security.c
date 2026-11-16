#include "tc_security.h"
#include "context_private.h"
#include "../tools/tc_security_diagnostics.h"
#include "tc_security_kdf.h"
#include "../src/commissioning_confirmation.h"
#include "gcm.h"
#include "test_gcm_seal.h"
#include "sm4.h"
#include "next_validation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Test-only cold restart and private inspection for fault injection. */
static void cold_restart(tcsec_context_t *object) {
    memset(object, 0, sizeof(*object));
}
static tcsec_private_context_t inspect(const tcsec_context_t *object) {
    tcsec_private_context_t value;
    memcpy(&value, object->_opaque, sizeof(value));
    return value;
}
static void corrupt_epoch(tcsec_context_t *object) {
    object->_opaque[offsetof(tcsec_private_context_t, current_epoch)] ^= 1u;
}

#define VECTOR_BUFFER_SIZE 4096u

/* TEST ONLY: one ordinary Space Packet accepted by the synthetic policy. */
static const uint8_t next_test_packet[16] = {
    0x10, 0x42, 0xc0, 0x01, 0x00, 0x09, 0x01, 0x01
};

typedef struct {
    tcsec_suite_t suite;
    uint8_t root[TCSEC_ROOT_KEY_LENGTH];
    size_t root_length;
    uint8_t ordinary_root[TCSEC_ROOT_KEY_LENGTH];
    size_t ordinary_root_length;
    tcsec_suite_t ordinary_suite;
    uint8_t prefix[TCSEC_NONCE_PREFIX_LENGTH];
    uint16_t spi;
    uint32_t iv_counter;
    uint16_t spacecraft_id;
    uint32_t root_version;
    uint32_t current_root_version;
    uint32_t security_epoch;
    uint16_t current_spi;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    size_t plaintext_length;
    uint8_t protected_frame[TCSEC_MAX_FRAME_LENGTH];
    size_t protected_frame_length;
} vector_t;

typedef struct {
    tcsec_config_t snapshot;
    tcsec_context_t *context_to_corrupt_on_load;
    tcsec_commit_result_t result;
    uint32_t calls;
    uint32_t budget_calls;
    tcsec_commit_kind_t last_kind;
    uint16_t last_spi;
    uint64_t transaction_id;
    tcsec_context_t *context_to_corrupt;
    uint8_t *plaintext_to_corrupt;
    uint8_t corrupt_context_during_commit;
    uint64_t monotonic_time_us;
} callbacks_t;

typedef struct {
    callbacks_t base;
    tcsec_context_t *secondary_context;
    const uint8_t *frame;
    size_t frame_length;
    uint8_t secondary_plaintext[TCSEC_MAX_FRAME_LENGTH];
    tcsec_result_t secondary_result;
    tcsec_status_t secondary_status;
    uint8_t invoked;
} reentrant_callbacks_t;

static int from_hex(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode_hex(const char *text, uint8_t *output, size_t capacity, size_t *length) {
    size_t text_length = strlen(text);
    size_t index;
    if ((text_length & 1u) != 0u || text_length / 2u > capacity) return 0;
    for (index = 0u; index < text_length; index += 2u) {
        int high = from_hex(text[index]);
        int low = from_hex(text[index + 1u]);
        if (high < 0 || low < 0) return 0;
        output[index / 2u] = (uint8_t)((high << 4) | low);
    }
    *length = text_length / 2u;
    return 1;
}

static tcsec_suite_t parse_suite(const char *value) {
    if (strcmp(value, "SM4_GCM_32") == 0)
        return TCSEC_SUITE_SM4_GCM_32;
    if (strcmp(value, "SM4_GCM") == 0) return TCSEC_SUITE_SM4_GCM;
    return (tcsec_suite_t)0xffffu;
}

static int load_vector(const char *path, vector_t *vector) {
    FILE *file = fopen(path, "rb");
    char line[VECTOR_BUFFER_SIZE];
    unsigned required = 0u;
    if (file == NULL) return 0;
    memset(vector, 0, sizeof(*vector));
    while (fgets(line, sizeof(line), file) != NULL) {
        char *equals;
        char *value;
        size_t length;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        equals = strchr(line, '=');
        if (equals == NULL) goto fail;
        *equals = '\0'; value = equals + 1;
        if (strcmp(line, "suite_id") == 0) {
            vector->suite = parse_suite(value); required |= 1u;
        } else if (strcmp(line, "root") == 0) {
            if (!decode_hex(value, vector->root, sizeof(vector->root), &vector->root_length)) goto fail;
            required |= 2u;
        } else if (strcmp(line, "ordinary_root") == 0) {
            if (!decode_hex(value, vector->ordinary_root, sizeof(vector->ordinary_root), &vector->ordinary_root_length)) goto fail;
        } else if (strcmp(line, "ordinary_suite") == 0) {
            vector->ordinary_suite = parse_suite(value);
        } else if (strcmp(line, "nonce_prefix") == 0) {
            if (!decode_hex(value, vector->prefix, sizeof(vector->prefix), &length) || length != sizeof(vector->prefix)) goto fail;
            required |= 4u;
        } else if (strcmp(line, "spi") == 0) {
            vector->spi = (uint16_t)strtoul(value, NULL, 16); required |= 8u;
        } else if (strcmp(line, "iv_counter") == 0) {
            vector->iv_counter = (uint32_t)strtoul(value, NULL, 16); required |= 16u;
        } else if (strcmp(line, "spacecraft_id") == 0) {
            vector->spacecraft_id = (uint16_t)strtoul(value, NULL, 16); required |= 32u;
        } else if (strcmp(line, "root_version") == 0) {
            vector->root_version = (uint32_t)strtoul(value, NULL, 10); required |= 64u;
        } else if (strcmp(line, "current_root_version") == 0) {
            vector->current_root_version = (uint32_t)strtoul(value, NULL, 10);
        } else if (strcmp(line, "security_epoch") == 0) {
            vector->security_epoch = (uint32_t)strtoul(value, NULL, 10); required |= 128u;
        } else if (strcmp(line, "current_spi") == 0) {
            vector->current_spi = (uint16_t)strtoul(value, NULL, 16);
        } else if (strcmp(line, "plaintext") == 0) {
            if (!decode_hex(value, vector->plaintext, sizeof(vector->plaintext), &vector->plaintext_length)) goto fail;
            required |= 256u;
        } else if (strcmp(line, "protected_frame") == 0) {
            if (!decode_hex(value, vector->protected_frame, sizeof(vector->protected_frame), &vector->protected_frame_length)) goto fail;
            required |= 512u;
        } else goto fail;
    }
    fclose(file);
    return required == 1023u;
fail:
    fclose(file);
    return 0;
}

static tcsec_commit_result_t commit_state(void *user, const tcsec_commit_t *commit) {
    callbacks_t *callbacks = (callbacks_t *)user;
    if (commit->kind == TCSEC_COMMIT_AUTH_BUDGET) {
        callbacks->budget_calls++;
        if (commit->spi == callbacks->snapshot.ordinary.current_spi)
            callbacks->snapshot.ordinary.current_auth_used = commit->auth_used;
        else
            callbacks->snapshot.ordinary.next_auth_used = commit->auth_used;
        return TCSEC_COMMIT_NEW;
    }
    callbacks->calls++;
    callbacks->last_kind = commit->kind;
    callbacks->last_spi = commit->spi;
    if (commit->root_prepare != NULL) callbacks->transaction_id = commit->root_prepare->transaction_id;
    if (callbacks->plaintext_to_corrupt != NULL) callbacks->plaintext_to_corrupt[0] ^= 1u;
    if (callbacks->corrupt_context_during_commit != 0u &&
        callbacks->context_to_corrupt != NULL)
        corrupt_epoch(callbacks->context_to_corrupt);
    return callbacks->result;
}

static tcsec_commit_result_t commit_reentrant(void *user, const tcsec_commit_t *commit) {
    reentrant_callbacks_t *callbacks = (reentrant_callbacks_t *)user;
    if (callbacks->invoked == 0u) {
        callbacks->invoked = 1u;
        callbacks->secondary_status = tcsec_receive(
            callbacks->secondary_context, callbacks->frame, callbacks->frame_length,
            callbacks->secondary_plaintext, sizeof(callbacks->secondary_plaintext),
            &callbacks->secondary_result);
    }
    return commit_state(&callbacks->base, commit);
}

static uint64_t monotonic_time_us(void *user) {
    callbacks_t *callbacks = (callbacks_t *)user;
    callbacks->monotonic_time_us += 10u;
    return callbacks->monotonic_time_us;
}

static tcsec_status_t load_snapshot(void *user, tcsec_config_t *config) {
    const callbacks_t *callbacks = user;
    *config = callbacks->snapshot;
    if (callbacks->context_to_corrupt_on_load != NULL)
        corrupt_epoch(callbacks->context_to_corrupt_on_load);
    return TCSEC_OK;
}

static tcsec_status_t init_context(tcsec_context_t *context,
                                  const tcsec_config_t *config,
                                  callbacks_t *fixture) {
    const tcsec_callbacks_t callbacks = {
        .load_state = load_snapshot,
        .commit_state = commit_state,
        .monotonic_time_us = monotonic_time_us,
        .user_context = fixture,
    };
    cold_restart(context);
    fixture->snapshot = *config;
    return tcsec_init(context, &callbacks);
}

static uint16_t frame_crc(const uint8_t *data, size_t length) {
    uint16_t crc = 0xffffu;
    size_t index;
    for (index = 0u; index < length; ++index) {
        uint8_t bit;
        crc ^= (uint16_t)data[index] << 8;
        for (bit = 0u; bit < 8u; ++bit)
            crc = (crc & 0x8000u) != 0u ? (uint16_t)((crc << 1) ^ 0x1021u) : (uint16_t)(crc << 1);
    }
    return crc;
}

static void set_frame_length(uint8_t header[TCSEC_PRIMARY_HEADER_LENGTH], size_t length) {
    uint16_t encoded = (uint16_t)(length - 1u);
    header[2] = (uint8_t)((header[2] & 0xfcu) | ((encoded >> 8) & 0x03u));
    header[3] = (uint8_t)encoded;
}

static int build_ordinary_frame(tcsec_suite_t suite, const uint8_t *key, const uint8_t prefix[6],
                                uint16_t spi, uint32_t epoch, uint32_t iv, const uint8_t *plain,
                                size_t n, uint8_t *frame, size_t *length) {
    uint8_t nonce[12], tag[16];
    uint16_t crc, control = (uint16_t)((epoch % 3u) << 14) | (uint16_t)(iv & 0x3fffu);
    size_t total = 13u + n;
    if (suite != TCSEC_SUITE_SM4_GCM_32 || n < 16u || total > 1024u)
        return 0;
    memset(frame, 0, total);
    frame[0] = 0x20;
    frame[1] = 1;
    frame[4] = 7;
    set_frame_length(frame, total);
    frame[5] = (uint8_t)(control >> 8);
    frame[6] = (uint8_t)control;
    memcpy(nonce, prefix, 6);
    nonce[6] = (uint8_t)(spi >> 8);
    nonce[7] = (uint8_t)spi;
    nonce[8] = (uint8_t)(iv >> 24);
    nonce[9] = (uint8_t)(iv >> 16);
    nonce[10] = (uint8_t)(iv >> 8);
    nonce[11] = (uint8_t)iv;
    if (!test_gcm_seal(key, nonce, frame, 7, plain, n, frame + 11, tag))
        return 0;
    memcpy(frame + 7, tag, 4);
    crc = frame_crc(frame, total - 2);
    frame[total - 2] = (uint8_t)(crc >> 8);
    frame[total - 1] = (uint8_t)crc;
    *length = total;
    return 1;
}

static void ordinary_config(tcsec_config_t *config, const vector_t *vector) {
    static const uint8_t recovery_root[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    memset(config, 0, sizeof(*config));
    memset(config->profile_digest, 0x5au, sizeof(config->profile_digest));
    config->ordinary.spacecraft_id = vector->spacecraft_id;
    memcpy(config->ordinary.operational_root, vector->root, vector->root_length);
    config->ordinary.root_version = vector->root_version;
    config->ordinary.current_epoch = vector->security_epoch;
    config->ordinary.current_spi = vector->spi;
    memcpy(config->ordinary.nonce_prefix, vector->prefix, sizeof(config->ordinary.nonce_prefix));
    memcpy(config->recovery.recovery_root, recovery_root, sizeof(recovery_root));
    config->recovery.root_version = 3u;
    config->recovery.spi = 0x7002u;
    memcpy(config->recovery.nonce_prefix, "RECOVR", 6u);
}

static int init_ordinary(tcsec_context_t *context, const vector_t *vector, callbacks_t *callbacks) {
    tcsec_config_t config;
    ordinary_config(&config, vector);
    return init_context(context, &config, callbacks) == TCSEC_OK;
}

static void recovery_config(tcsec_config_t *config, const vector_t *vector) {
    memset(config, 0, sizeof(*config));
    memset(config->profile_digest, 0x5au, sizeof(config->profile_digest));
    config->ordinary.spacecraft_id = vector->spacecraft_id;
    memcpy(config->ordinary.operational_root, vector->ordinary_root, vector->ordinary_root_length);
    config->ordinary.root_version = vector->current_root_version;
    config->ordinary.current_epoch = vector->security_epoch;
    config->ordinary.current_spi = vector->current_spi;
    memcpy(config->ordinary.nonce_prefix, "ORDNRY", 6u);
    memcpy(config->recovery.recovery_root, vector->root, vector->root_length);
    config->recovery.root_version = vector->root_version;
    config->recovery.spi = vector->spi;
    memcpy(config->recovery.nonce_prefix, vector->prefix, sizeof(config->recovery.nonce_prefix));
}

static int init_recovery(tcsec_context_t *context, const vector_t *vector, callbacks_t *callbacks) {
    tcsec_config_t config;
    recovery_config(&config, vector);
    return init_context(context, &config, callbacks) == TCSEC_OK;
}

static int init_recovery_restored(tcsec_context_t *context, const vector_t *vector,
                                  const tcsec_context_t *prepared, callbacks_t *callbacks) {
    tcsec_config_t config;
    recovery_config(&config, vector);
    config.ordinary.pending_root_present = inspect(prepared).pending_root_present;
    memcpy(config.ordinary.pending_operational_root, inspect(prepared).pending_root,
           TCSEC_ROOT_KEY_LENGTH);
    config.ordinary.pending_root_version = inspect(prepared).pending_root_version;
    config.ordinary.pending_transaction_id = inspect(prepared).pending_transaction_id;
    config.recovery.replay = inspect(prepared).recovery_replay;
    return init_context(context, &config, callbacks) == TCSEC_OK;
}

static int test_sm4_backend_contract(void) {
    static const uint8_t key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    static const uint8_t expected[16] = {
        0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46
    };
    tcsec_sm4_key_t context;
    uint8_t output[16];
    uint8_t recovered[16];
    const char *backend;
    if (tcsec_sm4_key_init(&context, key) != 0) return 0;
    backend = tcsec_sm4_backend_name(&context);
    if (backend == NULL ||
        (strcmp(backend, "software") != 0 && strcmp(backend, "armv7-neon") != 0)) return 0;
    tcsec_sm4_encrypt_with_key(&context, key, output);
    tcsec_sm4_decrypt_with_key(&context, output, recovered);
    tcsec_sm4_key_clear(&context);
    return memcmp(output, expected, sizeof(output)) == 0 &&
           memcmp(recovered, key, sizeof(recovered)) == 0;
}

static int test_shared_kdf_vectors(void) {
    static const uint8_t ordinary_expected[16] = {0xe6, 0x5e, 0x51, 0xda, 0x8d, 0x91, 0xab, 0x02,
                                                  0x65, 0xae, 0x2e, 0xdc, 0x06, 0xdf, 0x63, 0x45};
    static const uint8_t sm4_root[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    static const uint8_t sm4_expected[16] = {0xfd, 0x9d, 0xe8, 0x2c, 0x50, 0x9c, 0xc2, 0xb9,
                                             0xb7, 0xaf, 0xd9, 0x07, 0xa6, 0x3b, 0xaa, 0x7e};
    uint8_t output[16];
    if (tcsec_derive_ordinary_key(sm4_root, sizeof(sm4_root), 0x1234u, TCSEC_SUITE_SM4_GCM_32,
                                  0x2001u, 7u, 9u, output, sizeof(output)) != 0 ||
        memcmp(output, ordinary_expected, sizeof(ordinary_expected)) != 0)
        return 0;
    memset(output, 0, sizeof(output));
    return tcsec_derive_recovery_key(sm4_root, sizeof(sm4_root), 0x1234u,
                                     TCSEC_SUITE_SM4_GCM, 0x7002u, 3u,
                                     output, sizeof(output)) == 0 &&
           memcmp(output, sm4_expected, sizeof(sm4_expected)) == 0;
}

static int test_low_level_rejections(void) {
    uint8_t block[16] = {0u};
    uint8_t output[32] = {0u};
    uint8_t nonce[TCSEC_GCM_NONCE_LENGTH] = {0u};
    uint8_t tag[TCSEC_GCM_TAG_LENGTH] = {0u};
    tcsec_sm4_key_t key_context;
    tcsec_status_t status;
    if (tcsec_sm4_key_init(NULL, block) == 0 ||
        tcsec_sm4_key_init(&key_context, NULL) == 0 ||
        tcsec_sm4_encrypt_block(NULL, block, block) == 0 ||
        tcsec_sm4_encrypt_block(block, NULL, block) == 0 ||
        tcsec_sm4_encrypt_block(block, block, NULL) == 0) return 0;
    tcsec_sm4_key_clear(NULL);
    if (tcsec_gcm_open((tcsec_suite_t)0xffffu, block, nonce, NULL, 0u,
                       NULL, 0u, tag, NULL) == 0 ||
        tcsec_gcm_open(TCSEC_SUITE_SM4_GCM, NULL, nonce, NULL, 0u,
                       NULL, 0u, tag, NULL) == 0 ||
        tcsec_gcm_open(TCSEC_SUITE_SM4_GCM, block, nonce, NULL, 1u,
                       NULL, 0u, tag, NULL) == 0 ||
        tcsec_gcm_open(TCSEC_SUITE_SM4_GCM, block, nonce, NULL, 0u,
                       block, 1u, tag, NULL) == 0)
        return 0;
#if SIZE_MAX > UINT32_MAX
    if (tcsec_gcm_open(TCSEC_SUITE_SM4_GCM, block, nonce, NULL, 0u,
                       block, (size_t)UINT32_MAX * 16u,
                       tag, output) == 0)
        return 0;
#endif
    if (tcsec_derive_ordinary_key(block, 15u, 1u, TCSEC_SUITE_SM4_GCM_32, 1u, 1u, 1u, output,
                                  sizeof(output)) == 0 ||
        tcsec_derive_ordinary_key(block, 16u, 1u, TCSEC_SUITE_SM4_GCM, 1u, 1u, 1u, output,
                                  sizeof(output)) == 0 ||
        tcsec_derive_ordinary_key(block, 16u, 1u, TCSEC_SUITE_SM4_GCM_32, 1u, 1u, 1u, output,
                                  15u) == 0 ||
        tcsec_derive_recovery_key(block, 16u, 1u, TCSEC_SUITE_SM4_GCM_32, 1u, 1u, output,
                                  sizeof(output)) == 0 ||
        tcsec_derive_recovery_key(block, 16u, 1u, TCSEC_SUITE_SM4_GCM, 1u, 1u, output, 15u) == 0)
        return 0;
    for (status = TCSEC_OK; status <= TCSEC_PROFILE_MISMATCH;
         status = (tcsec_status_t)(status + 1))
        if (strcmp(tcsec_status_string(status), "UNKNOWN") == 0) return 0;
    return strcmp(tcsec_status_string((tcsec_status_t)-1), "UNKNOWN") == 0 &&
           strcmp(tcsec_status_string((tcsec_status_t)999), "UNKNOWN") == 0;
}

static int test_strict_configuration(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context = {0};
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    tcsec_callbacks_t invalid_callbacks = {.load_state = load_snapshot};
    const tcsec_callbacks_t missing_load = {.commit_state = commit_state};
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&config, &vector);
    if (tcsec_init(&context, NULL) != TCSEC_INVALID_ARGUMENT ||
        tcsec_init(&context, &missing_load) != TCSEC_MISSING_CALLBACK ||
        tcsec_init(&context, &invalid_callbacks) != TCSEC_MISSING_CALLBACK)
        return 0;
    config.ordinary.spacecraft_id = 0x0400u;
    if (init_context(&context, &config, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.pending_root_present = 1u;
    if (init_context(&context, &config, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.pending_root_version = 1u;
    if (init_context(&context, &config, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.current_epoch = UINT32_MAX;
    if (init_context(&context, &config, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.current_auth_used = TCSEC_ORDINARY_AUTH_LIMIT + 1u;
    if (init_context(&context, &config, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    return 1;
}

static int test_context_fault_detection(const char *path) {
    vector_t vector;
    tcsec_context_t context = {0};
    tcsec_result_t result;
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector) ||
        !init_ordinary(&context, &vector, &callbacks)) return 0;
    corrupt_epoch(&context);
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) !=
        TCSEC_STATE_INTEGRITY_FAILED) return 0;
    cold_restart(&context);
    return 1;
}

static int test_runtime_status(const char *path) {
    vector_t vector;
    tcsec_config_t replacement;
    tcsec_context_t context = {0};
    tcsec_result_t result;
    tcsec_runtime_status_t status;
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector) || !init_ordinary(&context, &vector, &callbacks) ||
        tcsec_get_runtime_status(&context, &status) != TCSEC_OK ||
        status.self_test != TCSEC_SELF_TEST_PASSED ||
        (status.crypto_backend != TCSEC_CRYPTO_BACKEND_SOFTWARE &&
         status.crypto_backend != TCSEC_CRYPTO_BACKEND_ARMV7_NEON) ||
        status.receive_count != 0u || status.current_spi != vector.spi ||
        status.next_spi != (uint16_t)(vector.spi + 1u) ||
        status.recovery_spi != 0x7002u ||
        memcmp(status.profile_digest, inspect(&context).profile_digest,
               TCSEC_PROFILE_DIGEST_LENGTH) != 0)
        return 0;
    if (tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_OK ||
        tcsec_get_runtime_status(&context, &status) != TCSEC_OK ||
        status.receive_count != 1u || status.last_receive_us != 10u ||
        status.max_receive_us != 10u || status.cycle_limit_exceeded_count != 0u ||
        status.clock_anomaly_count != 0u)
        return 0;
    ordinary_config(&replacement, &vector);
    replacement.profile_digest[0] ^= 1u;
    callbacks.snapshot = replacement;
    if (tcsec_reset(&context) != TCSEC_PROFILE_MISMATCH)
        return 0;
    cold_restart(&context);
    return tcsec_get_runtime_status(NULL, &status) == TCSEC_INVALID_ARGUMENT &&
           tcsec_get_runtime_status(&context, NULL) == TCSEC_INVALID_ARGUMENT;
}

static int test_receive_without_clock(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context = {0};
    tcsec_result_t result;
    tcsec_runtime_status_t status;
    callbacks_t callbacks = {.result = TCSEC_COMMIT_PERSISTENCE_FAILED};
    const tcsec_callbacks_t platform = {
        .load_state = load_snapshot, .commit_state = commit_state, .user_context = &callbacks,
    };
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&config, &vector);
    callbacks.snapshot = config;
    if (tcsec_init(&context, &platform) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_PERSISTENCE_FAILED ||
        result.plaintext_length != 0u || callbacks.calls != 1u)
        return 0;

    callbacks.result = TCSEC_COMMIT_NEW;
    if (tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_RECEPTION_PAUSED ||
        result.plaintext_length != 0u || callbacks.calls != 1u ||
        tcsec_reset(&context) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_OK ||
        result.plaintext_length != vector.plaintext_length ||
        memcmp(plaintext, vector.plaintext, vector.plaintext_length) != 0 ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_REPLAY_REJECTED ||
        callbacks.calls != 2u ||
        tcsec_get_runtime_status(&context, &status) != TCSEC_OK ||
        status.receive_count != 2u || status.last_receive_us != 0u ||
        status.max_receive_us != 0u || status.cycle_limit_exceeded_count != 0u ||
        status.clock_anomaly_count != 0u)
        return 0;

    cold_restart(&context);
    return 1;
}

static int test_reset_transaction(const char *path) {
    vector_t vector;
    tcsec_config_t replacement;
    tcsec_context_t context = {0};
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    tcsec_result_t result;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector) ||
        !init_ordinary(&context, &vector, &callbacks)) return 0;

    ordinary_config(&replacement, &vector);
    replacement.ordinary.current_epoch = UINT32_MAX;
    callbacks.snapshot = replacement;
    if (tcsec_reset(&context) != TCSEC_INVALID_CONFIGURATION ||
        inspect(&context).initialized == 0u || inspect(&context).current_spi != vector.spi ||
        inspect(&context).current_epoch != vector.security_epoch ||
        inspect(&context).callbacks.commit_state != commit_state ||
        inspect(&context).callbacks.user_context != &callbacks)
        return 0;

    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_RECEPTION_PAUSED ||
        result.plaintext_length != 0u || callbacks.calls != 0u) return 0;

    ordinary_config(&callbacks.snapshot, &vector);
    if (tcsec_reset(&context) != TCSEC_OK ||
        callbacks.calls != 0u || inspect(&context).current_replay.seen != 0u ||
        inspect(&context).callbacks.commit_state != commit_state ||
        inspect(&context).callbacks.user_context != &callbacks)
        return 0;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_OK ||
        callbacks.calls != 1u ||
        memcmp(plaintext, vector.plaintext, vector.plaintext_length) != 0)
        return 0;

    callbacks.context_to_corrupt_on_load = &context;
    if (tcsec_reset(&context) != TCSEC_STATE_INTEGRITY_FAILED ||
        tcsec_reset(&context) != TCSEC_STATE_INTEGRITY_FAILED ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED ||
        callbacks.calls != 1u)
        return 0;
    cold_restart(&context);
    return tcsec_reset(&context) == TCSEC_NOT_INITIALIZED;
}

static int test_ordinary_vector(const char *path) {
    vector_t vector;
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    tcsec_context_t context = {0};
    tcsec_result_t result;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t corrupted[TCSEC_MAX_FRAME_LENGTH];
    uint8_t far_frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_key[TCSEC_SM4_KEY_LENGTH];
    size_t next_length, far_length;
    tcsec_status_t status;
    if (!load_vector(path, &vector) || !init_ordinary(&context, &vector, &callbacks)) return 0;
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           plaintext, sizeof(plaintext), &result);
    if (status != TCSEC_OK || result.spi != vector.spi ||
        callbacks.last_kind != TCSEC_COMMIT_ORDINARY_REPLAY ||
        memcmp(plaintext, vector.plaintext, vector.plaintext_length) != 0) return 0;
    if (tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_REPLAY_REJECTED) return 0;
    if (tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, (uint16_t)(vector.spi + 1u),
                                  vector.security_epoch + 1u, vector.root_version, next_key,
                                  sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix, (uint16_t)(vector.spi + 1u),
                              vector.security_epoch + 1u, 1u, next_test_packet,
                              sizeof(next_test_packet), next_frame, &next_length))
        return 0;
    status = tcsec_receive(&context, next_frame, next_length, plaintext, sizeof(plaintext), &result);
    if (status != TCSEC_EPOCH_PROMOTED || result.security_epoch != vector.security_epoch + 1u ||
        callbacks.last_kind != TCSEC_COMMIT_EPOCH_PROMOTION || inspect(&context).current_spi != vector.spi + 1u)
        return 0;
    if (tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_ASSOCIATION_NOT_FOUND) return 0;

    memcpy(corrupted, vector.protected_frame, vector.protected_frame_length);
    corrupted[vector.protected_frame_length - 1u] ^= 1u;
    if (!init_ordinary(&context, &vector, &callbacks) ||
        tcsec_receive(&context, corrupted, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_FECF_INVALID) return 0;

    callbacks.result = TCSEC_COMMIT_PERSISTENCE_FAILED;
    callbacks.calls = 0u;
    memset(plaintext, 0xa5, sizeof(plaintext));
    if (!init_ordinary(&context, &vector, &callbacks) ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_PERSISTENCE_FAILED ||
        callbacks.calls != 1u || inspect(&context).current_replay.seen != 0u || plaintext[0] != 0u) return 0;

    callbacks.result = TCSEC_COMMIT_NEW;
    if (tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, vector.spi, vector.security_epoch,
                                  vector.root_version, next_key, sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix, vector.spi,
                              vector.security_epoch, TCSEC_MAX_FORWARD_JUMP + 1u, vector.plaintext,
                              vector.plaintext_length, far_frame, &far_length) ||
        !init_ordinary(&context, &vector, &callbacks) ||
        tcsec_receive(&context, far_frame, far_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_IV_FORWARD_JUMP_REJECTED)
        return 0;
    cold_restart(&context);
    return 1;
}

static int test_receive_boundaries_and_replay_motion(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context = {0};
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    tcsec_result_t result;
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    uint8_t working_key[TCSEC_SM4_KEY_LENGTH];
    size_t frame_length;
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&config, &vector);
    if (init_context(&context, &config, &callbacks) != TCSEC_OK)
        return 0;
    memcpy(frame, vector.protected_frame, vector.protected_frame_length);
    frame[3] ^= 1u;
    if (tcsec_receive(NULL, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_INVALID_ARGUMENT ||
        tcsec_receive(&context, NULL, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_INVALID_ARGUMENT ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), NULL) != TCSEC_INVALID_ARGUMENT ||
        tcsec_receive(&context, vector.protected_frame, 1u,
                      plaintext, sizeof(plaintext), &result) != TCSEC_FRAME_LENGTH_INVALID ||
        tcsec_receive(&context, vector.protected_frame, TCSEC_MAX_FRAME_LENGTH + 1u,
                      plaintext, sizeof(plaintext), &result) != TCSEC_FRAME_LENGTH_INVALID ||
        tcsec_receive(&context, frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_FRAME_LENGTH_INVALID ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      NULL, 0u, &result) != TCSEC_FRAME_LENGTH_INVALID ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, vector.plaintext_length - 1u, &result) != TCSEC_OUTPUT_TOO_SMALL)
        return 0;
    cold_restart(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.result = TCSEC_COMMIT_NEW;
    ordinary_config(&config, &vector);
    config.ordinary.replay.highest_iv = 100u;
    config.ordinary.replay.bitmap = 1u;
    config.ordinary.replay.seen = 1u;
    config.ordinary.current_auth_used = 2;
    if (init_context(&context, &config, &callbacks) != TCSEC_OK ||
        tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, vector.spi, vector.security_epoch,
                                  vector.root_version, working_key, sizeof(working_key)) != 0 ||
        !build_ordinary_frame(vector.suite, working_key, vector.prefix, vector.spi,
                              vector.security_epoch, 200u, vector.plaintext,
                              vector.plaintext_length, frame, &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_OK ||
        !build_ordinary_frame(vector.suite, working_key, vector.prefix, vector.spi,
                              vector.security_epoch, 199u, vector.plaintext,
                              vector.plaintext_length, frame, &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_OK ||
        !build_ordinary_frame(vector.suite, working_key, vector.prefix, vector.spi,
                              vector.security_epoch, 120u, vector.plaintext,
                              vector.plaintext_length, frame, &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_REPLAY_REJECTED)
        return 0;
    cold_restart(&context);

    ordinary_config(&config, &vector);
    config.ordinary.replay.highest_iv = 100u;
    config.ordinary.replay.bitmap = 1u;
    config.ordinary.replay.seen = 1u;
    config.ordinary.current_auth_used = 2;
    if (init_context(&context, &config, &callbacks) != TCSEC_OK ||
        !build_ordinary_frame(vector.suite, working_key, vector.prefix, vector.spi,
                              vector.security_epoch, 5000u, vector.plaintext,
                              vector.plaintext_length, frame, &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_IV_FORWARD_JUMP_REJECTED)
        return 0;
    cold_restart(&context);
    return 1;
}

static int test_callback_fault_detection(const char *path) {
    vector_t vector;
    tcsec_context_t context = {0};
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    tcsec_result_t result;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector)) return 0;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_ordinary(&context, &vector, &callbacks)) return 0;
    callbacks.plaintext_to_corrupt = plaintext;
    memset(plaintext, 0xa5, sizeof(plaintext));
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED ||
        plaintext[0] != 0u)
        return 0;
    cold_restart(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_ordinary(&context, &vector, &callbacks)) return 0;
    callbacks.context_to_corrupt = &context;
    callbacks.corrupt_context_during_commit = 1u;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    cold_restart(&context);
    return 1;
}

static int test_promotion_failure_paths(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context = {0};
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    tcsec_result_t result;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_key[TCSEC_SM4_KEY_LENGTH];
    size_t frame_length;
    if (!load_vector(path, &vector) ||
        tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, (uint16_t)(vector.spi + 1u),
                                  vector.security_epoch + 1u, vector.root_version, next_key,
                                  sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix, (uint16_t)(vector.spi + 1u),
                              vector.security_epoch + 1u, 1u, next_test_packet,
                              sizeof(next_test_packet), frame, &frame_length))
        return 0;

    callbacks.result = TCSEC_COMMIT_PERSISTENCE_FAILED;
    if (!init_ordinary(&context, &vector, &callbacks) ||
        tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_PERSISTENCE_FAILED)
        return 0;
    cold_restart(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_ordinary(&context, &vector, &callbacks)) return 0;
    callbacks.plaintext_to_corrupt = plaintext;
    if (tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    cold_restart(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_ordinary(&context, &vector, &callbacks)) return 0;
    callbacks.context_to_corrupt = &context;
    callbacks.corrupt_context_during_commit = 1u;
    if (tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    cold_restart(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.result = TCSEC_COMMIT_NEW;
    ordinary_config(&config, &vector);
    config.ordinary.current_epoch = UINT32_MAX - 1u;
    if (init_context(&context, &config, &callbacks) != TCSEC_OK ||
        tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, (uint16_t)(vector.spi + 1u), UINT32_MAX,
                                  vector.root_version, next_key, sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix, (uint16_t)(vector.spi + 1u),
                              UINT32_MAX, 1u, next_test_packet, sizeof(next_test_packet), frame,
                              &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_EPOCH_EXHAUSTED)
        return 0;
    cold_restart(&context);
    return 1;
}

static int test_spi_wrap(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context = {0};
    tcsec_result_t result;
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    uint8_t next_key[TCSEC_SM4_KEY_LENGTH];
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    size_t frame_length;
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.current_spi = UINT16_MAX;
    if (init_context(&context, &config, &callbacks) != TCSEC_OK ||
        tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, 0u, vector.security_epoch + 1u, vector.root_version,
                                  next_key, sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix, 0u, vector.security_epoch + 1u,
                              1u, next_test_packet, sizeof(next_test_packet), frame, &frame_length))
        return 0;
    if (tcsec_receive(&context, frame, frame_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_EPOCH_PROMOTED || inspect(&context).current_spi != 0u || result.spi != 0u ||
        memcmp(plaintext, next_test_packet, sizeof(next_test_packet)) != 0) return 0;
    cold_restart(&context);
    return 1;
}

/* The fixture models what the core can observe across the storage boundary.
 * The two write faults occur before publication and after publication but
 * before confirmation. The latter must never release plaintext twice. */
typedef enum {
    STORAGE_WRITABLE = 0,
    STORAGE_INTERRUPTED,
    STORAGE_CONFIRMATION_LOST
} storage_fault_t;

typedef struct {
    tcsec_config_t saved;
    tcsec_config_t cache;
    tcsec_status_t load_error;
    storage_fault_t fault;
    tcsec_commit_kind_t fault_kind;
    unsigned commits;
    uint64_t time_us;
} storage_fixture_t;

/* Test-visible scratch owned by the storage callbacks, never by the core. */
static void clear_storage_scratch(storage_fixture_t *storage) {
    volatile unsigned char *cursor = (volatile unsigned char *)&storage->cache;
    size_t length = sizeof(storage->cache);
    while (length-- != 0u) *cursor++ = 0u;
}

static tcsec_status_t load_storage(void *user, tcsec_config_t *config) {
    storage_fixture_t *storage = user;
    storage->cache = storage->saved;
    if (storage->load_error == TCSEC_OK) *config = storage->cache;
    clear_storage_scratch(storage);
    return storage->load_error;
}

static tcsec_commit_result_t commit_storage(void *user, const tcsec_commit_t *change) {
    storage_fixture_t *storage = user;
    storage->cache = storage->saved;
    int fault_applies = storage->fault_kind == 0 ? change->kind != TCSEC_COMMIT_AUTH_BUDGET
                                                 : change->kind == storage->fault_kind;
    tcsec_ordinary_config_t *ordinary = &storage->cache.ordinary;
    tcsec_commit_result_t result = TCSEC_COMMIT_REJECTED;
    if (change->kind != TCSEC_COMMIT_AUTH_BUDGET)
        storage->commits++;
    if (storage->fault == STORAGE_INTERRUPTED && fault_applies) {
        result = TCSEC_COMMIT_PERSISTENCE_FAILED;
        goto cleanup;
    }
    switch (change->kind) {
    case TCSEC_COMMIT_AUTH_BUDGET:
        if (change->auth_used > TCSEC_ORDINARY_AUTH_LIMIT)
            goto cleanup;
        if (change->spi == ordinary->current_spi) {
            if (change->auth_used != ordinary->current_auth_used + 2u)
                goto cleanup;
            ordinary->current_auth_used = change->auth_used;
        } else if (change->spi == (uint16_t)(ordinary->current_spi + 1u)) {
            if (change->auth_used != ordinary->next_auth_used + 2u)
                goto cleanup;
            ordinary->next_auth_used = change->auth_used;
        } else
            goto cleanup;
        break;
    case TCSEC_COMMIT_ORDINARY_REPLAY:
        ordinary->replay = change->replay;
        break;
    case TCSEC_COMMIT_ROOT_PREPARE:
        if (!ordinary->pending_root_present)
            ordinary->next_auth_used = 0;
        ordinary->pending_root_present = 1u;
        memcpy(ordinary->pending_operational_root, change->root_prepare->new_operational_root,
               sizeof(ordinary->pending_operational_root));
        ordinary->pending_root_version = change->root_prepare->new_root_version;
        ordinary->pending_transaction_id = change->root_prepare->transaction_id;
        storage->cache.recovery.replay = change->replay;
        break;
    case TCSEC_COMMIT_EPOCH_PROMOTION:
        ordinary->current_auth_used = ordinary->next_auth_used;
        ordinary->next_auth_used = 0;
        ordinary->current_spi = change->spi;
        ordinary->current_epoch = change->current_epoch;
        ordinary->root_version = change->root_version;
        ordinary->replay = change->replay;
        if (ordinary->pending_root_present != 0u) {
            memcpy(ordinary->operational_root, ordinary->pending_operational_root,
                   sizeof(ordinary->operational_root));
            ordinary->pending_root_present = 0u;
            memset(ordinary->pending_operational_root, 0, sizeof(ordinary->pending_operational_root));
            ordinary->pending_root_version = 0u;
            ordinary->pending_transaction_id = 0u;
        }
        break;
    default:
        goto cleanup;
    }
    storage->saved = storage->cache;
    result = storage->fault == STORAGE_CONFIRMATION_LOST && fault_applies ? TCSEC_COMMIT_UNCERTAIN
                                                                          : TCSEC_COMMIT_NEW;
cleanup:
    clear_storage_scratch(storage);
    return result;
}

static uint64_t storage_time(void *user) {
    storage_fixture_t *storage = user;
    storage->time_us += 5u;
    return storage->time_us;
}

static int test_storage_callback_cleanup(const char *path) {
    vector_t vector;
    storage_fixture_t storage = {0};
    tcsec_config_t output = {0}, initial;
    tcsec_commit_t change = {0};
    const unsigned char empty[sizeof(storage.cache)] = {0};
    const unsigned char empty_output[sizeof(output)] = {0};
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&storage.saved, &vector);
    initial = storage.saved;
    /* Direct calls prove cleanup happens before returning to the core. */
    if (load_storage(&storage, &output) != TCSEC_OK ||
        memcmp(&output, &initial, sizeof(output)) != 0 ||
        memcmp(&storage.cache, empty, sizeof(empty)) != 0) return 0;
    memset(&output, 0, sizeof(output));
    storage.load_error = TCSEC_STATE_INTEGRITY_FAILED;
    if (load_storage(&storage, &output) != TCSEC_STATE_INTEGRITY_FAILED ||
        memcmp(&output, empty_output, sizeof(output)) != 0 ||
        memcmp(&storage.cache, empty, sizeof(empty)) != 0) return 0;
    change.kind = (tcsec_commit_kind_t)99;
    if (commit_storage(&storage, &change) != TCSEC_COMMIT_REJECTED ||
        memcmp(&storage.saved, &initial, sizeof(initial)) != 0 ||
        memcmp(&storage.cache, empty, sizeof(empty)) != 0) return 0;
    change.kind = TCSEC_COMMIT_ORDINARY_REPLAY;
    change.replay.seen = 1;
    change.replay.highest_iv = 9;
    change.replay.bitmap = 1;
    storage.fault = STORAGE_INTERRUPTED;
    if (commit_storage(&storage, &change) != TCSEC_COMMIT_PERSISTENCE_FAILED ||
        memcmp(&storage.saved, &initial, sizeof(initial)) != 0 ||
        memcmp(&storage.cache, empty, sizeof(empty)) != 0) return 0;
    storage.fault = STORAGE_CONFIRMATION_LOST;
    if (commit_storage(&storage, &change) != TCSEC_COMMIT_UNCERTAIN ||
        storage.saved.ordinary.replay.highest_iv != 9 ||
        memcmp(&storage.cache, empty, sizeof(empty)) != 0) return 0;
    storage.fault = STORAGE_WRITABLE;
    change.replay.highest_iv = 10;
    if (commit_storage(&storage, &change) != TCSEC_COMMIT_NEW ||
        storage.saved.ordinary.replay.highest_iv != 10 ||
        memcmp(&storage.cache, empty, sizeof(empty)) != 0) return 0;
    return 1;
}

static int test_storage_recovery(const char *path) {
    vector_t vector;
    storage_fixture_t storage = {0};
    tcsec_context_t context = {0};
    tcsec_runtime_status_t status;
    tcsec_result_t result;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH];
    const uint8_t empty_cache[sizeof(storage.cache)] = {0};
    const uint8_t empty_context[sizeof(context)] = {0};
    tcsec_callbacks_t callbacks = {
        .load_state = load_storage, .commit_state = commit_storage,
        .monotonic_time_us = storage_time,
        .user_context = &storage,
    };
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&storage.saved, &vector);
    if (tcsec_init(NULL, &callbacks) != TCSEC_INVALID_ARGUMENT ||
        tcsec_reset(NULL) != TCSEC_INVALID_ARGUMENT ||
        tcsec_reset(&context) != TCSEC_NOT_INITIALIZED ||
        tcsec_receive(NULL, vector.protected_frame, vector.protected_frame_length,
                      output, sizeof(output), &result) != TCSEC_INVALID_ARGUMENT)
        return 0;


    storage.load_error = TCSEC_PERSISTENCE_FAILED;
    if (tcsec_init(&context, &callbacks) != TCSEC_PERSISTENCE_FAILED ||
        memcmp(&storage.cache, empty_cache, sizeof(empty_cache)) != 0 ||
        memcmp(&context, empty_context, sizeof(empty_context)) != 0 ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      output, sizeof(output), &result) != TCSEC_NOT_INITIALIZED)
        return 0;
    storage.load_error = TCSEC_OK;
    if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
        tcsec_init(&context, &callbacks) != TCSEC_ALREADY_INITIALIZED)
        return 0;

    storage.fault = STORAGE_INTERRUPTED;
    if (tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      output, sizeof(output), &result) != TCSEC_PERSISTENCE_FAILED ||
        result.plaintext_length != 0u || output[0] != 0u ||
        storage.commits != 1u || storage.saved.ordinary.replay.seen != 0u ||
        tcsec_get_runtime_status(&context, &status) != TCSEC_OK ||
        status.reception_paused != 1u || status.receive_count != 1u || status.last_receive_us != 5u ||
        memcmp(&storage.cache, empty_cache, sizeof(empty_cache)) != 0)
        return 0;

    storage.load_error = TCSEC_STATE_INTEGRITY_FAILED;
    if (tcsec_reset(&context) != TCSEC_STATE_INTEGRITY_FAILED ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      output, sizeof(output), &result) != TCSEC_RECEPTION_PAUSED ||
        storage.commits != 1u)
        return 0;
    storage.load_error = TCSEC_OK;
    storage.fault = STORAGE_CONFIRMATION_LOST;
    if (tcsec_reset(&context) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      output, sizeof(output), &result) != TCSEC_STORAGE_COMMIT_UNCERTAIN ||
        result.plaintext_length != 0u || output[0] != 0u || storage.commits != 2u ||
        storage.saved.ordinary.replay.highest_iv != vector.iv_counter)
        return 0;
    storage.fault = STORAGE_WRITABLE;
    if (tcsec_reset(&context) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      output, sizeof(output), &result) != TCSEC_REPLAY_REJECTED ||
        storage.commits != 2u)
        return 0;

    cold_restart(&context);
    if (memcmp(&storage.cache, empty_cache, sizeof(empty_cache)) != 0 ||
        memcmp(&context, empty_context, sizeof(empty_context)) != 0)
        return 0;
    callbacks.monotonic_time_us = NULL;
    if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      output, sizeof(output), &result) != TCSEC_REPLAY_REJECTED ||
        tcsec_get_runtime_status(&context, &status) != TCSEC_OK ||
        status.reception_paused != 0u || status.receive_count != 1u || status.last_receive_us != 0u)
        return 0;
    cold_restart(&context);
    return 1;
}

static int test_storage_rotation(const char *path) {
    vector_t vector;
    storage_fixture_t storage = {0};
    tcsec_context_t context = {0};
    const tcsec_callbacks_t callbacks = {
        .load_state = load_storage, .commit_state = commit_storage,
        .user_context = &storage,
    };
    tcsec_result_t result;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH], frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t key[TCSEC_SM4_KEY_LENGTH];
    size_t length;
    if (!load_vector(path, &vector)) return 0;
    recovery_config(&storage.saved, &vector);
    if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      output, sizeof(output), &result) != TCSEC_ROOT_PREPARED ||
        result.plaintext_length != 0u || !storage.saved.ordinary.pending_root_present ||
        !storage.saved.recovery.replay.seen)
        return 0;
    cold_restart(&context);
    const tcsec_ordinary_config_t *ordinary = &storage.saved.ordinary;
    const uint16_t next_spi = (uint16_t)(ordinary->current_spi + 1u);
    if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
        tcsec_derive_ordinary_key(ordinary->pending_operational_root, TCSEC_ROOT_KEY_LENGTH,
                                  ordinary->spacecraft_id, TCSEC_SUITE_SM4_GCM_32, next_spi,
                                  ordinary->current_epoch + 1u, ordinary->pending_root_version, key,
                                  sizeof(key)) != 0 ||
        !build_ordinary_frame(TCSEC_SUITE_SM4_GCM_32, key, ordinary->nonce_prefix, next_spi,
                              ordinary->current_epoch + 1u, 1u, next_test_packet,
                              sizeof(next_test_packet), frame, &length) ||
        tcsec_receive(&context, frame, length, output, sizeof(output), &result) !=
            TCSEC_EPOCH_PROMOTED ||
        memcmp(output, next_test_packet, sizeof(next_test_packet)) != 0 ||
        ordinary->pending_root_present != 0u || ordinary->current_spi != next_spi ||
        storage.commits != 2u)
        return 0;
    cold_restart(&context);
    if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
        tcsec_receive(&context, frame, length, output, sizeof(output), &result) != TCSEC_REPLAY_REJECTED)
        return 0;
    cold_restart(&context);
    return 1;
}

static int test_recovery_vector(const char *path) {
    vector_t vector;
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    tcsec_context_t context = {0};
    tcsec_result_t result;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH];
    uint8_t corrupted[TCSEC_MAX_FRAME_LENGTH];
    uint8_t header_corrupted[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_key[TCSEC_SM4_KEY_LENGTH];
    tcsec_context_t restored = {0};
    size_t next_length;
    uint16_t crc;
    tcsec_status_t status;
    if (!load_vector(path, &vector) || !init_recovery(&context, &vector, &callbacks)) return 0;
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           output, sizeof(output), &result);
    if (status != TCSEC_ROOT_PREPARED || callbacks.last_kind != TCSEC_COMMIT_ROOT_PREPARE ||
        callbacks.transaction_id != 0x0102030405060708ULL || inspect(&context).pending_root_present == 0u)
        return 0;
    if (tcsec_derive_ordinary_key(
            &vector.plaintext[TCSEC_ROOT_PREPARE_FIXED_LENGTH],
            vector.plaintext_length - TCSEC_ROOT_PREPARE_FIXED_LENGTH, vector.spacecraft_id,
            TCSEC_SUITE_SM4_GCM_32, (uint16_t)(vector.current_spi + 1u), vector.security_epoch + 1u,
            inspect(&context).pending_root_version, next_key, sizeof(next_key)) != 0 ||
        !build_ordinary_frame(TCSEC_SUITE_SM4_GCM_32, next_key, (const uint8_t *)"ORDNRY",
                              (uint16_t)(vector.current_spi + 1u), vector.security_epoch + 1u, 1u,
                              next_test_packet, sizeof(next_test_packet), next_frame,
                              &next_length) ||
        !init_recovery_restored(&restored, &vector, &context, &callbacks))
        return 0;
    status = tcsec_receive(&restored, next_frame, next_length, output, sizeof(output), &result);
    if (status != TCSEC_EPOCH_PROMOTED || inspect(&restored).pending_root_present != 0u ||
        inspect(&restored).current_root_version != inspect(&context).pending_root_version ||
        memcmp(output, next_test_packet, sizeof(next_test_packet)) != 0) return 0;
    cold_restart(&restored);
    memcpy(corrupted, vector.protected_frame, vector.protected_frame_length);
    corrupted[TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH] ^= 1u;
    crc = frame_crc(corrupted, vector.protected_frame_length - TCSEC_FECF_LENGTH);
    corrupted[vector.protected_frame_length - 2u] = (uint8_t)(crc >> 8);
    corrupted[vector.protected_frame_length - 1u] = (uint8_t)crc;
    callbacks.calls = 0u;
    if (!init_recovery(&context, &vector, &callbacks)) return 0;
    status = tcsec_receive(&context, corrupted, vector.protected_frame_length,
                           output, sizeof(output), &result);
    if (status != TCSEC_AUTHENTICATION_FAILED || callbacks.calls != 0u) return 0;
    memcpy(header_corrupted, vector.protected_frame, vector.protected_frame_length);
    header_corrupted[4] ^= 1u;
    crc = frame_crc(header_corrupted, vector.protected_frame_length - TCSEC_FECF_LENGTH);
    header_corrupted[vector.protected_frame_length - 2u] = (uint8_t)(crc >> 8);
    header_corrupted[vector.protected_frame_length - 1u] = (uint8_t)crc;
    if (!init_recovery(&context, &vector, &callbacks) ||
        tcsec_receive(&context, header_corrupted, vector.protected_frame_length,
                      output, sizeof(output), &result) != TCSEC_AUTHENTICATION_FAILED ||
        callbacks.calls != 0u) return 0;
    callbacks.result = TCSEC_COMMIT_PERSISTENCE_FAILED;
    if (!init_recovery(&context, &vector, &callbacks)) return 0;
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           output, sizeof(output), &result);
    if (status != TCSEC_PERSISTENCE_FAILED || inspect(&context).recovery_replay.seen != 0u ||
        inspect(&context).pending_root_present != 0u) return 0;
    cold_restart(&context);
    return 1;
}

static int test_recovery_rejections(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context = {0};
    callbacks_t callbacks = {.result = TCSEC_COMMIT_REJECTED};
    tcsec_result_t result;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector) ||
        !init_recovery(&context, &vector, &callbacks)) return 0;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_STATE_COMMIT_REJECTED)
        return 0;
    cold_restart(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.result = TCSEC_COMMIT_NEW;
    recovery_config(&config, &vector);
    config.ordinary.root_version++;
    callbacks.result = TCSEC_COMMIT_NEW;
    if (init_context(&context, &config, &callbacks) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_ROOT_PREPARE_REJECTED)
        return 0;
    cold_restart(&context);

    callbacks.result = (tcsec_commit_result_t)99;
    if (!init_recovery(&context, &vector, &callbacks) ||
        tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_CALLBACK_RESULT_INVALID)
        return 0;
    cold_restart(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_recovery(&context, &vector, &callbacks)) return 0;
    callbacks.context_to_corrupt = &context;
    callbacks.corrupt_context_during_commit = 1u;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    cold_restart(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.result = TCSEC_COMMIT_NEW;
    recovery_config(&config, &vector);
    config.ordinary.pending_root_present = 1u;
    memcpy(config.ordinary.pending_operational_root,
           vector.ordinary_root, TCSEC_ROOT_KEY_LENGTH);
    config.ordinary.pending_operational_root[0] ^= 1u;
    config.ordinary.pending_root_version = vector.current_root_version + 1u;
    config.ordinary.pending_transaction_id = UINT64_C(0x8877665544332211);
    if (init_context(&context, &config, &callbacks) != TCSEC_OK)
        return 0;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_ROOT_PREPARE_REJECTED)
        return 0;
    cold_restart(&context);
    return 1;
}

static int test_distinct_context_reentrancy(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t primary = {0};
    tcsec_context_t secondary = {0};
    callbacks_t secondary_callbacks = {.result = TCSEC_COMMIT_NEW};
    reentrant_callbacks_t primary_callbacks;
    tcsec_result_t primary_result;
    uint8_t primary_plaintext[TCSEC_MAX_FRAME_LENGTH];
    tcsec_status_t primary_status;
    if (!load_vector(path, &vector) ||
        !init_ordinary(&secondary, &vector, &secondary_callbacks)) return 0;
    memset(&primary_callbacks, 0, sizeof(primary_callbacks));
    primary_callbacks.base.result = TCSEC_COMMIT_NEW;
    primary_callbacks.secondary_context = &secondary;
    primary_callbacks.frame = vector.protected_frame;
    primary_callbacks.frame_length = vector.protected_frame_length;
    ordinary_config(&config, &vector);
    primary_callbacks.base.snapshot = config;
    const tcsec_callbacks_t nested = {
        .load_state = load_snapshot, .commit_state = commit_reentrant,
        .monotonic_time_us = monotonic_time_us, .user_context = &primary_callbacks,
    };
    if (tcsec_init(&primary, &nested) != TCSEC_OK) return 0;
    primary_status = tcsec_receive(&primary, vector.protected_frame,
                                   vector.protected_frame_length,
                                   primary_plaintext, sizeof(primary_plaintext),
                                   &primary_result);
    if (primary_status != TCSEC_OK || primary_callbacks.invoked == 0u ||
        primary_callbacks.secondary_status != TCSEC_OK ||
        primary_callbacks.base.calls != 1u || secondary_callbacks.calls != 1u ||
        memcmp(primary_plaintext, vector.plaintext, vector.plaintext_length) != 0 ||
        memcmp(primary_callbacks.secondary_plaintext, vector.plaintext,
               vector.plaintext_length) != 0) return 0;
    cold_restart(&primary);
    cold_restart(&secondary);
    return 1;
}

static int test_next_validation(const char *path) {
    static const struct { size_t offset; uint8_t mask; } mutations[] = {
        {0u, 0x20u}, {0u, 0x10u}, {0u, 0x08u}, {1u, 1u}, {2u, 0x40u},
        {4u, 1u}, {5u, 1u}, {6u, 0x80u}, {7u, 0x80u}, {8u, 1u}
    };
    vector_t vector;
    callbacks_t callbacks = {.result = TCSEC_COMMIT_NEW};
    tcsec_context_t context = {0};
    tcsec_result_t result;
    uint8_t key[TCSEC_SM4_KEY_LENGTH];
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t packet[sizeof(next_test_packet)] = {0};
    uint8_t output[sizeof(next_test_packet)];
    uint8_t header[TCSEC_PRIMARY_HEADER_LENGTH] = {0x20u, 0x01u, 0u, 0u, 0u};
    const uint8_t zero[sizeof(output)] = {0};
    size_t length, index;

    if (!load_vector(path, &vector) || !init_ordinary(&context, &vector, &callbacks))
        return 0;
    if (tcsec_next_plaintext_allowed(vector.spacecraft_id, NULL, packet, sizeof(packet)) ||
        tcsec_next_plaintext_allowed(vector.spacecraft_id, header, NULL, sizeof(packet)) ||
        tcsec_next_plaintext_allowed(vector.spacecraft_id, header, packet, 6u) ||
        tcsec_next_plaintext_allowed(vector.spacecraft_id, header, packet, TCSEC_MAX_FRAME_LENGTH))
        return 0;
    if (tcsec_next_plaintext_allowed((uint16_t)(vector.spacecraft_id ^ 1u), header,
                                     next_test_packet, sizeof(next_test_packet)))
        return 0;
    header[0] ^= 0x04u;
    if (tcsec_next_plaintext_allowed(vector.spacecraft_id, header, next_test_packet,
                                     sizeof(next_test_packet)))
        return 0;
    header[0] ^= 0x04u;
    memcpy(packet, next_test_packet, sizeof(packet));
    packet[0] |= 7u;
    packet[1] = 0xffu;
    if (tcsec_next_plaintext_allowed(vector.spacecraft_id, header, packet, sizeof(packet)))
        return 0;

    if (tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, (uint16_t)(vector.spi + 1u),
                                  vector.security_epoch + 1u, vector.root_version,
                                  key, sizeof(key)) != 0)
        return 0;
    for (index = 0u; index <= sizeof(mutations) / sizeof(mutations[0]); ++index) {
        uint16_t crc;
        memcpy(packet, next_test_packet, sizeof(packet));
        if (index < sizeof(mutations) / sizeof(mutations[0]))
            packet[mutations[index].offset] ^= mutations[index].mask;
        if (!build_ordinary_frame(vector.suite, key, vector.prefix, (uint16_t)(vector.spi + 1u),
                                  vector.security_epoch + 1u, 1u, packet, sizeof(packet), frame,
                                  &length))
            return 0;
        if (index == sizeof(mutations) / sizeof(mutations[0])) {
            frame[2] ^= 4u; /* VCID changes without changing the frame length. */
            crc = frame_crc(frame, length - TCSEC_FECF_LENGTH);
            frame[length - 2u] = (uint8_t)(crc >> 8);
            frame[length - 1u] = (uint8_t)crc;
        }
        memset(output, 0xa5, sizeof(output));
        if (tcsec_receive(&context, frame, length, output, sizeof(output), &result) !=
                (index == sizeof(mutations) / sizeof(mutations[0]) ? TCSEC_AUTHENTICATION_FAILED
                                                                   : TCSEC_PLAINTEXT_REJECTED) ||
            result.plaintext_length != 0u || memcmp(output, zero, sizeof(output)) != 0 ||
            callbacks.calls != 0u || inspect(&context).current_spi != vector.spi ||
            inspect(&context).current_epoch != vector.security_epoch ||
            inspect(&context).next_replay.seen != 0u)
            return 0;
    }
    memcpy(packet, next_test_packet, sizeof(packet));
    packet[6] = 2u; /* A second ordinary command can also trigger promotion. */
    if (!build_ordinary_frame(vector.suite, key, vector.prefix, (uint16_t)(vector.spi + 1u),
                              vector.security_epoch + 1u, 1u, packet, sizeof(packet), frame,
                              &length) ||
        tcsec_receive(&context, frame, length, output, sizeof(output), &result) !=
            TCSEC_EPOCH_PROMOTED ||
        callbacks.calls != 1u || inspect(&context).current_spi != (uint16_t)(vector.spi + 1u) ||
        result.plaintext_length != sizeof(packet) || memcmp(output, packet, sizeof(packet)) != 0)
        return 0;
    cold_restart(&context);
    return 1;
}

static int test_review_contract(const char *path) {
    vector_t vector;
    tcsec_context_t context = {0};
    storage_fixture_t storage = {0};
    tcsec_runtime_status_t runtime;
    tcsec_result_t result;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH];
    unsigned index;
    static const tcsec_status_t errors[] = {
        TCSEC_STORAGE_UNAVAILABLE, TCSEC_STORAGE_NO_QUORUM,
        TCSEC_STORAGE_ROLLBACK_DETECTED, TCSEC_STORAGE_NOT_COMMISSIONED,
    };
    tcsec_callbacks_t platform = {
        .load_state = load_storage,
        .commit_state = commit_storage,
        .user_context = &storage,
    };
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&storage.saved, &vector);
    memset(output, 0xa5, sizeof(output));
    memset(&result, 0xa5, sizeof(result));
    if (tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                     output, sizeof(output), &result) != TCSEC_NOT_INITIALIZED ||
        result.plaintext_length != 0 || output[0] != 0 ||
        tcsec_get_runtime_status(&context, &runtime) != TCSEC_NOT_INITIALIZED) return 0;
    for (index = 0; index < sizeof(errors)/sizeof(errors[0]); ++index) {
        storage.load_error = errors[index];
        if (tcsec_init(&context, &platform) != errors[index]) return 0;
    }
    storage.load_error = TCSEC_INVALID_ARGUMENT;
    if (tcsec_init(&context, &platform) != TCSEC_CALLBACK_RESULT_INVALID) return 0;
    storage.load_error = TCSEC_OK;
    if (tcsec_init(&context, &platform) != TCSEC_OK) return 0;
    storage.fault = STORAGE_CONFIRMATION_LOST;
    if (tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                     output, sizeof(output), &result) != TCSEC_STORAGE_COMMIT_UNCERTAIN ||
        tcsec_get_runtime_status(&context, &runtime) != TCSEC_OK ||
        runtime.last_status != TCSEC_STORAGE_COMMIT_UNCERTAIN || !runtime.reception_paused ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                     output, sizeof(output), &result) != TCSEC_RECEPTION_PAUSED) return 0;
    storage.fault = STORAGE_WRITABLE;
    if (tcsec_reset(&context) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                     output, sizeof(output), &result) != TCSEC_REPLAY_REJECTED) return 0;
    cold_restart(&context);

    return 1;
}

static uint64_t backwards_clock(void *user) {
    callbacks_t *fixture = user;
    return 100u - ++fixture->monotonic_time_us;
}

static int test_review_recovery_boundaries(const char *path) {
    vector_t vector;
    tcsec_context_t context = {0};
    callbacks_t fixture = {.result=TCSEC_COMMIT_NEW};
    tcsec_config_t config;
    tcsec_result_t result;
    tcsec_runtime_status_t runtime;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH];
    const tcsec_callbacks_t callbacks = {.load_state=load_snapshot, .commit_state=commit_state,
        .monotonic_time_us=backwards_clock, .user_context=&fixture};
    if (!load_vector(path,&vector)) return 0;
    recovery_config(&config, &vector);
    config.ordinary.current_epoch = UINT32_MAX-1u;
    if (init_context(&context,&config,&fixture) != TCSEC_OK ||
        tcsec_receive(&context,vector.protected_frame,vector.protected_frame_length,
            output,sizeof(output),&result) != TCSEC_EPOCH_EXHAUSTED || fixture.calls != 0) return 0;
    cold_restart(&context);
    recovery_config(&config,&vector);
    config.ordinary.pending_operational_root[0] = 1;
    if (init_context(&context,&config,&fixture) != TCSEC_INVALID_CONFIGURATION) return 0;
    recovery_config(&config,&vector);
    config.ordinary.pending_root_present = 1;
    config.ordinary.pending_root_version = vector.current_root_version+1;
    config.ordinary.pending_transaction_id = UINT64_C(0x0102030405060708);
    memcpy(config.ordinary.pending_operational_root,
           vector.plaintext+TCSEC_ROOT_PREPARE_FIXED_LENGTH,16);
    config.ordinary.pending_operational_root[0] ^= 1;
    if (init_context(&context,&config,&fixture) != TCSEC_OK ||
        tcsec_receive(&context,vector.protected_frame,vector.protected_frame_length,
            output,sizeof(output),&result) != TCSEC_ROOT_PREPARE_REJECTED || fixture.calls != 0) return 0;
    cold_restart(&context);
    recovery_config(&fixture.snapshot,&vector);
    if (tcsec_init(&context,&callbacks) != TCSEC_OK ||
        tcsec_receive(&context,vector.protected_frame,vector.protected_frame_length,
            output,sizeof(output),&result) != TCSEC_ROOT_PREPARED ||
        tcsec_get_runtime_status(&context,&runtime) != TCSEC_OK ||
        runtime.clock_anomaly_count != 1 || runtime.last_receive_us != 0) return 0;
    corrupt_epoch(&context);
    if (tcsec_get_runtime_status(&context,&runtime) != TCSEC_STATE_INTEGRITY_FAILED ||
        tcsec_init(&context,&callbacks) != TCSEC_STATE_INTEGRITY_FAILED) return 0;
    cold_restart(&context);
    return 1;
}

static int test_authentication_budget(const char *path) {
    vector_t vector;
    tcsec_context_t context = {0};
    storage_fixture_t storage = {0};
    tcsec_callbacks_t callbacks = {
        .load_state = load_storage, .commit_state = commit_storage, .user_context = &storage};
    tcsec_result_t result;
    uint8_t output[1024], frame[1024], key[16];
    size_t length;
    unsigned fault;
    if (!load_vector(path, &vector))
        return 0;
    ordinary_config(&storage.saved, &vector);
    storage.saved.ordinary.current_auth_used = 2046;
    if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_OK ||
        storage.saved.ordinary.current_auth_used != 2048)
        return 0;
    if (tcsec_derive_ordinary_key(vector.root, 16, vector.spacecraft_id, vector.suite, vector.spi,
                                  vector.security_epoch, vector.root_version, key, 16) != 0 ||
        !build_ordinary_frame(vector.suite, key, vector.prefix, vector.spi, vector.security_epoch,
                              vector.iv_counter + 1, vector.plaintext, vector.plaintext_length,
                              frame, &length) ||
        tcsec_reset(&context) != TCSEC_OK ||
        tcsec_receive(&context, frame, length, output, sizeof(output), &result) !=
            TCSEC_AUTH_BUDGET_EXHAUSTED ||
        output[0] != 0)
        return 0;
    /* NEXT remains independent even when CURRENT's verification allowance is spent. */
    if (tcsec_derive_ordinary_key(vector.root, 16, vector.spacecraft_id, vector.suite,
                                  (uint16_t)(vector.spi + 1), vector.security_epoch + 1,
                                  vector.root_version, key, 16) != 0 ||
        !build_ordinary_frame(vector.suite, key, vector.prefix, (uint16_t)(vector.spi + 1),
                              vector.security_epoch + 1, 1, next_test_packet, 16, frame, &length) ||
        tcsec_receive(&context, frame, length, output, sizeof(output), &result) !=
            TCSEC_EPOCH_PROMOTED ||
        storage.saved.ordinary.current_auth_used != 2 ||
        storage.saved.ordinary.next_auth_used != 0 || tcsec_reset(&context) != TCSEC_OK)
        return 0;
    for (fault = STORAGE_INTERRUPTED; fault <= STORAGE_CONFIRMATION_LOST; fault++) {
        cold_restart(&context);
        memset(&storage, 0, sizeof(storage));
        ordinary_config(&storage.saved, &vector);
        storage.fault = (storage_fault_t)fault;
        storage.fault_kind = TCSEC_COMMIT_AUTH_BUDGET;
        if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
            tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length, output,
                          sizeof(output), &result) != (fault == STORAGE_INTERRUPTED
                                                           ? TCSEC_PERSISTENCE_FAILED
                                                           : TCSEC_STORAGE_COMMIT_UNCERTAIN) ||
            result.plaintext_length != 0 || output[0] != 0 ||
            storage.saved.ordinary.replay.seen != 0)
            return 0;
        storage.fault = STORAGE_WRITABLE;
        if (tcsec_reset(&context) != TCSEC_OK ||
            tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length, output,
                          sizeof(output), &result) != TCSEC_OK ||
            storage.saved.ordinary.current_auth_used != (fault == STORAGE_INTERRUPTED ? 2u : 4u))
            return 0;
    }
    cold_restart(&context);
    ordinary_config(&storage.saved, &vector);
    storage.saved.ordinary.current_auth_used = 1;
    if (tcsec_init(&context, &callbacks) != TCSEC_INVALID_CONFIGURATION)
        return 0;
    ordinary_config(&storage.saved, &vector);
    storage.saved.ordinary.next_auth_used = 2049;
    if (tcsec_init(&context, &callbacks) != TCSEC_INVALID_CONFIGURATION)
        return 0;
    ordinary_config(&storage.saved, &vector);
    storage.saved.ordinary.replay.seen = 1;
    storage.saved.ordinary.replay.bitmap = 1;
    if (tcsec_init(&context, &callbacks) != TCSEC_INVALID_CONFIGURATION)
        return 0;
    return 1;
}

static int test_root_retry_preserves_budget(const char *path) {
    vector_t v;
    storage_fixture_t store = {0};
    tcsec_context_t context = {0};
    tcsec_result_t result;
    tcsec_callbacks_t callbacks = {
        .load_state = load_storage, .commit_state = commit_storage, .user_context = &store};
    uint8_t output[1024], frame[1024], key[16], nonce[12], tag[16], packet[16];
    size_t length;
    uint16_t crc;
    uint32_t iv;
    if (!load_vector(path, &v))
        return 0;
    recovery_config(&store.saved, &v);
    store.saved.ordinary.current_auth_used = 2048;
    store.saved.ordinary.next_auth_used = 2048;
    if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
        tcsec_receive(&context, v.protected_frame, v.protected_frame_length, output, sizeof(output),
                      &result) != TCSEC_ROOT_PREPARED ||
        store.saved.ordinary.current_auth_used != 2048 || store.saved.ordinary.next_auth_used != 0)
        return 0;
    if (tcsec_derive_ordinary_key(v.plaintext + 25, 16, v.spacecraft_id, TCSEC_SUITE_SM4_GCM_32,
                                  (uint16_t)(v.current_spi + 1), v.security_epoch + 1, 8, key,
                                  16) != 0)
        return 0;
    memcpy(packet, next_test_packet, 16);
    packet[6] = 3;
    if (!build_ordinary_frame(TCSEC_SUITE_SM4_GCM_32, key, (const uint8_t *)"ORDNRY",
                              (uint16_t)(v.current_spi + 1), v.security_epoch + 1, 1, packet, 16,
                              frame, &length) ||
        tcsec_receive(&context, frame, length, output, sizeof(output), &result) !=
            TCSEC_PLAINTEXT_REJECTED ||
        store.saved.ordinary.next_auth_used != 2)
        return 0;
    /* Same authenticated transaction, fresh Recovery nonce: preserve spent NEXT quota. */
    memcpy(frame, v.protected_frame, v.protected_frame_length);
    iv = v.iv_counter + 1;
    frame[7] = (uint8_t)(iv >> 24);
    frame[8] = (uint8_t)(iv >> 16);
    frame[9] = (uint8_t)(iv >> 8);
    frame[10] = (uint8_t)iv;
    memcpy(nonce, v.prefix, 6);
    nonce[6] = (uint8_t)(v.spi >> 8);
    nonce[7] = (uint8_t)v.spi;
    memcpy(nonce + 8, frame + 7, 4);
    if (tcsec_derive_recovery_key(v.root, 16, v.spacecraft_id, TCSEC_SUITE_SM4_GCM, v.spi,
                                  v.root_version, key, 16) != 0 ||
        !test_gcm_seal(key, nonce, frame, 11, v.plaintext, 41, frame + 11, tag))
        return 0;
    memcpy(frame + 52, tag, 16);
    crc = frame_crc(frame, 68);
    frame[68] = (uint8_t)(crc >> 8);
    frame[69] = (uint8_t)crc;
    if (tcsec_receive(&context, frame, 70, output, sizeof(output), &result) !=
            TCSEC_ROOT_PREPARED ||
        store.saved.ordinary.next_auth_used != 2 || inspect(&context).next_auth_used != 2 ||
        tcsec_reset(&context) != TCSEC_OK)
        return 0;
    if (tcsec_derive_ordinary_key(v.plaintext + 25, 16, v.spacecraft_id, TCSEC_SUITE_SM4_GCM_32,
                                  (uint16_t)(v.current_spi + 1), v.security_epoch + 1, 8, key,
                                  16) != 0 ||
        !build_ordinary_frame(TCSEC_SUITE_SM4_GCM_32, key, (const uint8_t *)"ORDNRY",
                              (uint16_t)(v.current_spi + 1), v.security_epoch + 1, 2,
                              next_test_packet, 16, frame, &length) ||
        tcsec_receive(&context, frame, length, output, sizeof(output), &result) !=
            TCSEC_EPOCH_PROMOTED ||
        store.saved.ordinary.current_auth_used != 4 || store.saved.ordinary.next_auth_used != 0)
        return 0;
    return 1;
}

#include "storage_quorum_model.h"

static int test_commissioning_confirmation(void) {
    static const uint8_t ground[32] = {
        0x3e,0x5f,0xe9,0xac,0xfd,0xe8,0xe5,0x2d,0xae,0x20,0xfe,0x21,0xb9,0xc0,0x08,0x98,
        0xe8,0xd8,0xfb,0x0e,0x56,0xf1,0x5e,0x92,0xff,0xe1,0x4e,0x1d,0xa5,0xcb,0x4f,0xbc
    };
    static const uint8_t flight[32] = {
        0x88,0x0a,0xd9,0x9d,0x91,0x80,0xe7,0xe9,0x37,0x02,0x2f,0x76,0x55,0xf2,0x61,0xf4,
        0x0c,0x88,0x5d,0x4c,0x08,0x27,0xf0,0xd0,0x16,0xd4,0x92,0xb9,0x88,0x5c,0x01,0x5d
    };
    uint8_t current[16], recovery[16], transcript[192] = {0}, proof[32];
    unsigned int i;
    memset(current, 0x11, sizeof(current));
    memset(recovery, 0x22, sizeof(recovery));
    for (i = 0; i < 6u; ++i) transcript[i * 32u] = (uint8_t)(i + 1u);
    if (tcsec_confirm_flight(current, recovery, transcript, proof) != 0 || memcmp(proof, flight, sizeof(proof)) != 0 ||
        tcsec_confirm_verify_ground(current, recovery, transcript, ground) != 0 ||
        tcsec_confirm_verify_ground(current, recovery, transcript, flight) == 0 ||
        tcsec_confirm_verify_ground(current, recovery, transcript, NULL) == 0 ||
        tcsec_confirm_flight(current, recovery, transcript, NULL) == 0 ||
        tcsec_confirm_flight(current, current, transcript, proof) == 0 ||
        memcmp(proof, (uint8_t[32]){0}, sizeof(proof)) != 0) return 0;
    transcript[160] = 7u;
    if (tcsec_confirm_verify_ground(current, recovery, transcript, ground) == 0) return 0;
    transcript[160] = 5u;
    if (tcsec_confirm_flight(current, recovery, transcript, proof) == 0) return 0;
    transcript[160] = 0u;
    return tcsec_confirm_flight(current, recovery, transcript, proof) != 0;
}

int main(int argc, char **argv) {
    int index;
    if (argc != 3) {
        fprintf(stderr, "expected SM4-GCM32 ordinary and SM4-GCM recovery vector paths\n");
        return 1;
    }
    if (!test_root_retry_preserves_budget(argv[2])) {
        fprintf(stderr, "Root retry budget tests failed\n");
        return 1;
    }
    if (!test_authentication_budget(argv[1])) {
        fprintf(stderr, "Authentication budget tests failed\n");
        return 1;
    }
    if (!test_next_validation(argv[1])) {
        fprintf(stderr, "Next admission and promotion tests failed\n");
        return 1;
    }
    if (!test_sm4_backend_contract()) {
        fprintf(stderr, "SM4 backend dispatch contract failed\n");
        return 1;
    }
    if (!test_shared_kdf_vectors()) {
        fprintf(stderr, "CMAC counter KDF shared vector failed\n");
        return 1;
    }
    if (!test_commissioning_confirmation()) {
        fprintf(stderr, "Commissioning confirmation vectors failed\n");
        return 1;
    }
    if (!test_low_level_rejections()) {
        fprintf(stderr, "low-level rejection tests failed\n");
        return 1;
    }
    if (!test_strict_configuration(argv[1])) {
        fprintf(stderr, "invalid TC configuration was accepted\n");
        return 1;
    }
    if (!test_context_fault_detection(argv[1])) {
        fprintf(stderr, "context fault was not detected\n");
        return 1;
    }
    if (!test_runtime_status(argv[1])) {
        fprintf(stderr, "runtime status/telemetry tests failed\n");
        return 1;
    }
    if (!test_receive_without_clock(argv[1])) {
        fprintf(stderr, "optional clock tests failed\n");
        return 1;
    }
    if (!test_receive_boundaries_and_replay_motion(argv[1])) {
        fprintf(stderr, "receive boundary/replay motion tests failed\n");
        return 1;
    }
    if (!test_callback_fault_detection(argv[1])) {
        fprintf(stderr, "callback fault was not detected\n");
        return 1;
    }
    if (!test_promotion_failure_paths(argv[1])) {
        fprintf(stderr, "promotion failure-path tests failed\n");
        return 1;
    }
    if (!test_spi_wrap(argv[1])) {
        fprintf(stderr, "full 16-bit SPI wrap test failed\n");
        return 1;
    }
    if (!test_reset_transaction(argv[1])) {
        fprintf(stderr, "transactional context reset test failed\n");
        return 1;
    }
    if (!test_storage_callback_cleanup(argv[1]) || !test_storage_recovery(argv[1]) || !test_storage_rotation(argv[2]) || !test_quorum_powercuts(argv[1], argv[2]) || !test_review_contract(argv[1]) || !test_review_recovery_boundaries(argv[2])) {
        fprintf(stderr, "flight storage callback tests failed\n");
        return 1;
    }
    if (!test_distinct_context_reentrancy(argv[1])) {
        fprintf(stderr, "distinct-context reentrancy test failed\n");
        return 1;
    }
    for (index = 1; index < 2; ++index) {
        if (!test_ordinary_vector(argv[index])) {
            fprintf(stderr, "ordinary automatic epoch vector failed: %s\n", argv[index]);
            return 1;
        }
    }
    for (index = 2; index < argc; ++index) {
        if (!test_recovery_vector(argv[index])) {
            fprintf(stderr, "authenticated root prepare vector failed: %s\n", argv[index]);
            return 1;
        }
        if (!test_recovery_rejections(argv[index])) {
            fprintf(stderr, "recovery rejection tests failed: %s\n", argv[index]);
            return 1;
        }
    }
    printf("TC Current/Next auto-promotion and Recovery GCM tests passed\n");
    return 0;
}
