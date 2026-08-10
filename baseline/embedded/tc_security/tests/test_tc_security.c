#include "tc_security.h"
#include "tc_security_kdf.h"
#include "aes256.h"
#include "sm4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VECTOR_BUFFER_SIZE 4096u

typedef struct {
    tcsec_suite_t suite;
    uint8_t root[TCSEC_MAX_KEY_LENGTH];
    size_t root_length;
    uint8_t ordinary_root[TCSEC_MAX_KEY_LENGTH];
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
    int accept_plaintext;
    tcsec_commit_result_t result;
    uint32_t calls;
    tcsec_commit_kind_t last_kind;
    uint16_t last_spi;
    uint64_t transaction_id;
} callbacks_t;

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
    if (strcmp(value, "AES_256_CTR") == 0) return TCSEC_SUITE_AES_256_CTR;
    if (strcmp(value, "SM4_CTR") == 0) return TCSEC_SUITE_SM4_CTR;
    if (strcmp(value, "AES_256_GCM") == 0) return TCSEC_SUITE_AES_256_GCM;
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

static int validate_plaintext(void *user,
                              const uint8_t primary_header[TCSEC_PRIMARY_HEADER_LENGTH],
                              const uint8_t *plaintext, size_t length) {
    callbacks_t *callbacks = (callbacks_t *)user;
    return callbacks->accept_plaintext && primary_header[0] == 0x20u &&
           length >= 2u && plaintext[0] == 0xcau && plaintext[1] == 0xfeu;
}

static tcsec_commit_result_t commit_state(void *user, const tcsec_commit_t *commit) {
    callbacks_t *callbacks = (callbacks_t *)user;
    callbacks->calls++;
    callbacks->last_kind = commit->kind;
    callbacks->last_spi = commit->spi;
    if (commit->root_prepare != NULL) callbacks->transaction_id = commit->root_prepare->transaction_id;
    return callbacks->result;
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

static int build_ordinary_frame(tcsec_suite_t suite, const uint8_t *key,
                                const uint8_t prefix[TCSEC_NONCE_PREFIX_LENGTH],
                                uint16_t spi, uint32_t iv, const uint8_t *plaintext,
                                size_t plaintext_length, uint8_t *frame, size_t *frame_length) {
    uint8_t counter[16] = {0};
    uint16_t crc;
    size_t total = TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH +
                   plaintext_length + TCSEC_FECF_LENGTH;
    if (total > TCSEC_MAX_FRAME_LENGTH) return 0;
    memset(frame, 0, total);
    frame[0] = 0x20u; frame[1] = 0x01u; frame[4] = 0x07u;
    set_frame_length(frame, total);
    frame[5] = (uint8_t)(spi >> 8); frame[6] = (uint8_t)spi;
    frame[7] = (uint8_t)(iv >> 24); frame[8] = (uint8_t)(iv >> 16);
    frame[9] = (uint8_t)(iv >> 8); frame[10] = (uint8_t)iv;
    memcpy(counter, prefix, TCSEC_NONCE_PREFIX_LENGTH);
    counter[6] = (uint8_t)(spi >> 8); counter[7] = (uint8_t)spi;
    counter[8] = (uint8_t)(iv >> 24); counter[9] = (uint8_t)(iv >> 16);
    counter[10] = (uint8_t)(iv >> 8); counter[11] = (uint8_t)iv;
    if ((suite == TCSEC_SUITE_AES_256_CTR &&
         tcsec_aes256_ctr_xor(key, counter, plaintext, &frame[11], plaintext_length) != 0) ||
        (suite == TCSEC_SUITE_SM4_CTR &&
         tcsec_sm4_ctr_xor(key, counter, plaintext, &frame[11], plaintext_length) != 0)) return 0;
    crc = frame_crc(frame, total - 2u);
    frame[total - 2u] = (uint8_t)(crc >> 8); frame[total - 1u] = (uint8_t)crc;
    *frame_length = total;
    return 1;
}

static void ordinary_config(tcsec_config_t *config, const vector_t *vector) {
    static const uint8_t recovery_root[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    memset(config, 0, sizeof(*config));
    config->ordinary.spacecraft_id = vector->spacecraft_id;
    config->ordinary.suite = vector->suite;
    memcpy(config->ordinary.operational_root, vector->root, vector->root_length);
    config->ordinary.operational_root_length = vector->root_length;
    config->ordinary.root_version = vector->root_version;
    config->ordinary.current_epoch = vector->security_epoch;
    config->ordinary.current_spi = vector->spi;
    memcpy(config->ordinary.nonce_prefix, vector->prefix, sizeof(config->ordinary.nonce_prefix));
    config->recovery.suite = TCSEC_SUITE_SM4_GCM;
    memcpy(config->recovery.recovery_root, recovery_root, sizeof(recovery_root));
    config->recovery.recovery_root_length = sizeof(recovery_root);
    config->recovery.root_version = 3u;
    config->recovery.spi = 0x7002u;
    memcpy(config->recovery.nonce_prefix, "RECOVR", 6u);
}

static int init_ordinary(tcsec_context_t *context, const vector_t *vector, callbacks_t *callbacks) {
    tcsec_config_t config;
    ordinary_config(&config, vector);
    return tcsec_init(context, &config, validate_plaintext, commit_state, callbacks) == TCSEC_OK;
}

static void recovery_config(tcsec_config_t *config, const vector_t *vector) {
    memset(config, 0, sizeof(*config));
    config->ordinary.spacecraft_id = vector->spacecraft_id;
    config->ordinary.suite = vector->ordinary_suite;
    memcpy(config->ordinary.operational_root, vector->ordinary_root, vector->ordinary_root_length);
    config->ordinary.operational_root_length = vector->ordinary_root_length;
    config->ordinary.root_version = vector->current_root_version;
    config->ordinary.current_epoch = vector->security_epoch;
    config->ordinary.current_spi = vector->current_spi;
    memcpy(config->ordinary.nonce_prefix, "ORDNRY", 6u);
    config->recovery.suite = vector->suite;
    memcpy(config->recovery.recovery_root, vector->root, vector->root_length);
    config->recovery.recovery_root_length = vector->root_length;
    config->recovery.root_version = vector->root_version;
    config->recovery.spi = vector->spi;
    memcpy(config->recovery.nonce_prefix, vector->prefix, sizeof(config->recovery.nonce_prefix));
}

static int init_recovery(tcsec_context_t *context, const vector_t *vector, callbacks_t *callbacks) {
    tcsec_config_t config;
    recovery_config(&config, vector);
    return tcsec_init(context, &config, validate_plaintext, commit_state, callbacks) == TCSEC_OK;
}

static int init_recovery_restored(tcsec_context_t *context, const vector_t *vector,
                                  const tcsec_context_t *prepared, callbacks_t *callbacks) {
    tcsec_config_t config;
    recovery_config(&config, vector);
    config.ordinary.pending_root_present = prepared->pending_root_present;
    config.ordinary.pending_suite = prepared->next_suite;
    memcpy(config.ordinary.pending_operational_root, prepared->pending_root,
           prepared->pending_root_length);
    config.ordinary.pending_operational_root_length = prepared->pending_root_length;
    config.ordinary.pending_root_version = prepared->pending_root_version;
    config.ordinary.pending_transaction_id = prepared->pending_transaction_id;
    config.recovery.replay = prepared->recovery_replay;
    return tcsec_init(context, &config, validate_plaintext, commit_state, callbacks) == TCSEC_OK;
}

static int test_nist_aes256_ctr(void) {
    static const uint8_t key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const uint8_t counter[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    static const uint8_t plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t expected[16] = {
        0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28
    };
    uint8_t output[16];
    return tcsec_aes256_ctr_xor(key, counter, plaintext, output, sizeof(output)) == 0 &&
           memcmp(output, expected, sizeof(output)) == 0;
}

static int test_sm4_ctr(void) {
    static const uint8_t key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    static const uint8_t counter[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    static const uint8_t expected[16] = {
        0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,
        0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46
    };
    uint8_t input[16] = {0u};
    uint8_t output[16];
    return tcsec_sm4_ctr_xor(key, counter, input, output, sizeof(output)) == 0 &&
           memcmp(output, expected, sizeof(output)) == 0;
}

static int test_shared_kdf_vectors(void) {
    static const uint8_t aes_root[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t aes_expected[32] = {
        0x6d,0x02,0xd7,0xa8,0x48,0x79,0x63,0x31,0xe9,0xb4,0x66,0xba,0xe9,0x12,0x1c,0x92,
        0xa8,0xc6,0x75,0x77,0x67,0xe1,0x8c,0x6a,0x1c,0x63,0x3a,0x23,0xbc,0x0e,0x5c,0xeb
    };
    static const uint8_t sm4_root[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    static const uint8_t sm4_expected[16] = {
        0x17,0x35,0x37,0xc6,0x3f,0x1e,0x50,0xad,0x36,0x29,0xcf,0xdc,0x49,0x11,0x8d,0x2b
    };
    uint8_t output[32];
    if (tcsec_derive_ordinary_key(aes_root, sizeof(aes_root), 0x1234u,
                                  TCSEC_SUITE_AES_256_CTR, 0x2001u, 7u, 9u,
                                  output, sizeof(output)) != 0 ||
        memcmp(output, aes_expected, sizeof(aes_expected)) != 0) return 0;
    memset(output, 0, sizeof(output));
    return tcsec_derive_recovery_key(sm4_root, sizeof(sm4_root), 0x1234u,
                                     TCSEC_SUITE_SM4_GCM, 0x7002u, 3u,
                                     output, sizeof(output)) == 0 &&
           memcmp(output, sm4_expected, sizeof(sm4_expected)) == 0;
}

static int test_strict_configuration(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context;
    callbacks_t callbacks = {1, TCSEC_COMMIT_NEW, 0u, 0, 0u, 0u};
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.pending_root_present = 1u;
    if (tcsec_init(&context, &config, validate_plaintext, commit_state, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.pending_root_version = 1u;
    if (tcsec_init(&context, &config, validate_plaintext, commit_state, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.current_epoch = UINT32_MAX;
    if (tcsec_init(&context, &config, validate_plaintext, commit_state, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.recovery.spi = (uint16_t)(config.ordinary.current_spi + 1u);
    return tcsec_init(&context, &config, validate_plaintext, commit_state, &callbacks) ==
           TCSEC_INVALID_CONFIGURATION;
}

static int test_ordinary_vector(const char *path) {
    vector_t vector;
    callbacks_t callbacks = {1, TCSEC_COMMIT_NEW, 0u, 0, 0u, 0u};
    tcsec_context_t context;
    tcsec_result_t result;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t corrupted[TCSEC_MAX_FRAME_LENGTH];
    uint8_t far_frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_key[TCSEC_MAX_KEY_LENGTH];
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
                                  vector.security_epoch + 1u, vector.root_version,
                                  next_key, sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix,
                              (uint16_t)(vector.spi + 1u), 1u, vector.plaintext,
                              vector.plaintext_length, next_frame, &next_length)) return 0;
    status = tcsec_receive(&context, next_frame, next_length, plaintext, sizeof(plaintext), &result);
    if (status != TCSEC_EPOCH_PROMOTED || result.security_epoch != vector.security_epoch + 1u ||
        callbacks.last_kind != TCSEC_COMMIT_EPOCH_PROMOTION || context.current_spi != vector.spi + 1u)
        return 0;
    if (tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_ASSOCIATION_NOT_FOUND) return 0;

    memcpy(corrupted, vector.protected_frame, vector.protected_frame_length);
    corrupted[vector.protected_frame_length - 1u] ^= 1u;
    if (!init_ordinary(&context, &vector, &callbacks) ||
        tcsec_receive(&context, corrupted, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_FECF_INVALID) return 0;

    callbacks.accept_plaintext = 0;
    callbacks.calls = 0u;
    if (!init_ordinary(&context, &vector, &callbacks) ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_PLAINTEXT_REJECTED ||
        callbacks.calls != 0u) return 0;

    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_PERSISTENCE_FAILED;
    callbacks.calls = 0u;
    memset(plaintext, 0xa5, sizeof(plaintext));
    if (!init_ordinary(&context, &vector, &callbacks) ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_PERSISTENCE_FAILED ||
        callbacks.calls != 1u || context.current_replay.seen != 0u || plaintext[0] != 0u) return 0;

    callbacks.result = TCSEC_COMMIT_NEW;
    if (tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, vector.spi, vector.security_epoch,
                                  vector.root_version, next_key, sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix, vector.spi,
                              TCSEC_MAX_FORWARD_JUMP + 1u, vector.plaintext,
                              vector.plaintext_length, far_frame, &far_length) ||
        !init_ordinary(&context, &vector, &callbacks) ||
        tcsec_receive(&context, far_frame, far_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_IV_FORWARD_JUMP_REJECTED) return 0;
    tcsec_clear(&context);
    return 1;
}

static int test_spi_wrap(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context;
    tcsec_result_t result;
    callbacks_t callbacks = {1, TCSEC_COMMIT_NEW, 0u, 0, 0u, 0u};
    uint8_t next_key[TCSEC_MAX_KEY_LENGTH];
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    size_t frame_length;
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.current_spi = UINT16_MAX;
    if (tcsec_init(&context, &config, validate_plaintext, commit_state, &callbacks) != TCSEC_OK ||
        tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, 0u, vector.security_epoch + 1u,
                                  vector.root_version, next_key, sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix, 0u, 1u,
                              vector.plaintext, vector.plaintext_length,
                              frame, &frame_length)) return 0;
    if (tcsec_receive(&context, frame, frame_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_EPOCH_PROMOTED || context.current_spi != 0u || result.spi != 0u ||
        memcmp(plaintext, vector.plaintext, vector.plaintext_length) != 0) return 0;
    tcsec_clear(&context);
    return 1;
}

static int test_recovery_vector(const char *path) {
    vector_t vector;
    callbacks_t callbacks = {1, TCSEC_COMMIT_NEW, 0u, 0, 0u, 0u};
    tcsec_context_t context;
    tcsec_result_t result;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH];
    uint8_t corrupted[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_key[TCSEC_MAX_KEY_LENGTH];
    static const uint8_t command[] = {0xca, 0xfe, 0x01, 0x02};
    tcsec_context_t restored;
    size_t next_length;
    uint16_t crc;
    tcsec_status_t status;
    if (!load_vector(path, &vector) || !init_recovery(&context, &vector, &callbacks)) return 0;
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           output, sizeof(output), &result);
    if (status != TCSEC_ROOT_PREPARED || callbacks.last_kind != TCSEC_COMMIT_ROOT_PREPARE ||
        callbacks.transaction_id != 0x0102030405060708ULL || context.pending_root_present == 0u)
        return 0;
    if (tcsec_derive_ordinary_key(&vector.plaintext[TCSEC_ROOT_PREPARE_FIXED_LENGTH],
                                  vector.plaintext_length - TCSEC_ROOT_PREPARE_FIXED_LENGTH,
                                  vector.spacecraft_id, context.next_suite,
                                  (uint16_t)(vector.current_spi + 1u), vector.security_epoch + 1u,
                                  context.pending_root_version, next_key, sizeof(next_key)) != 0 ||
        !build_ordinary_frame(context.next_suite, next_key, (const uint8_t *)"ORDNRY",
                              (uint16_t)(vector.current_spi + 1u), 1u, command, sizeof(command),
                              next_frame, &next_length) ||
        !init_recovery_restored(&restored, &vector, &context, &callbacks)) return 0;
    status = tcsec_receive(&restored, next_frame, next_length, output, sizeof(output), &result);
    if (status != TCSEC_EPOCH_PROMOTED || restored.pending_root_present != 0u ||
        restored.current_root_version != context.pending_root_version ||
        memcmp(output, command, sizeof(command)) != 0) return 0;
    tcsec_clear(&restored);
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
    callbacks.result = TCSEC_COMMIT_PERSISTENCE_FAILED;
    if (!init_recovery(&context, &vector, &callbacks)) return 0;
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           output, sizeof(output), &result);
    if (status != TCSEC_PERSISTENCE_FAILED || context.recovery_replay.seen != 0u ||
        context.pending_root_present != 0u) return 0;
    tcsec_clear(&context);
    return 1;
}

int main(int argc, char **argv) {
    int index;
    if (argc != 5) {
        fprintf(stderr, "expected ordinary and recovery AES/SM4 vector paths\n");
        return 1;
    }
    if (!test_nist_aes256_ctr()) {
        fprintf(stderr, "AES-256-CTR known-answer test failed\n");
        return 1;
    }
    if (!test_sm4_ctr()) {
        fprintf(stderr, "SM4-CTR known-answer test failed\n");
        return 1;
    }
    if (!test_shared_kdf_vectors()) {
        fprintf(stderr, "CMAC counter KDF shared vector failed\n");
        return 1;
    }
    if (!test_strict_configuration(argv[1])) {
        fprintf(stderr, "invalid TC configuration was accepted\n");
        return 1;
    }
    if (!test_spi_wrap(argv[1])) {
        fprintf(stderr, "full 16-bit SPI wrap test failed\n");
        return 1;
    }
    for (index = 1; index < 3; ++index) {
        if (!test_ordinary_vector(argv[index])) {
            fprintf(stderr, "ordinary automatic epoch vector failed: %s\n", argv[index]);
            return 1;
        }
    }
    for (index = 3; index < argc; ++index) {
        if (!test_recovery_vector(argv[index])) {
            fprintf(stderr, "authenticated root prepare vector failed: %s\n", argv[index]);
            return 1;
        }
    }
    printf("TC Current/Next auto-promotion and Recovery GCM tests passed\n");
    return 0;
}
