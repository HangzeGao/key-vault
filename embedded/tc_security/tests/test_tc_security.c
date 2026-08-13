#include "tc_security.h"
#include "tc_security_nvm.h"
#include "tc_security_kdf.h"
#include "gcm.h"
#include "hctr.h"
#include "sm4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VECTOR_BUFFER_SIZE 4096u

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
    int accept_plaintext;
    tcsec_commit_result_t result;
    uint32_t calls;
    tcsec_commit_kind_t last_kind;
    uint16_t last_spi;
    uint64_t transaction_id;
    tcsec_context_t *context_to_corrupt;
    uint8_t *validated_plaintext;
    size_t validated_plaintext_length;
    uint8_t corrupt_context_during_validation;
    uint8_t corrupt_context_during_commit;
    uint8_t corrupt_plaintext_during_commit;
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
    if (strcmp(value, "SM4_HCTR") == 0) return TCSEC_SUITE_SM4_HCTR;
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
    callbacks->validated_plaintext = (uint8_t *)plaintext;
    callbacks->validated_plaintext_length = length;
    if (callbacks->corrupt_context_during_validation != 0u &&
        callbacks->context_to_corrupt != NULL)
        callbacks->context_to_corrupt->current_epoch ^= 1u;
    return callbacks->accept_plaintext && primary_header[0] == 0x20u &&
           length >= 2u && plaintext[0] == 0xcau && plaintext[1] == 0xfeu;
}

static int validate_plaintext_reentrant(void *user,
                                        const uint8_t primary_header[TCSEC_PRIMARY_HEADER_LENGTH],
                                        const uint8_t *plaintext, size_t length) {
    reentrant_callbacks_t *callbacks = (reentrant_callbacks_t *)user;
    if (callbacks->invoked == 0u) {
        callbacks->invoked = 1u;
        callbacks->secondary_status = tcsec_receive(
            callbacks->secondary_context, callbacks->frame, callbacks->frame_length,
            callbacks->secondary_plaintext, sizeof(callbacks->secondary_plaintext),
            &callbacks->secondary_result);
    }
    return callbacks->base.accept_plaintext && primary_header[0] == 0x20u &&
           length >= 2u && plaintext[0] == 0xcau && plaintext[1] == 0xfeu;
}

static tcsec_commit_result_t commit_state(void *user, const tcsec_commit_t *commit) {
    callbacks_t *callbacks = (callbacks_t *)user;
    callbacks->calls++;
    callbacks->last_kind = commit->kind;
    callbacks->last_spi = commit->spi;
    if (commit->root_prepare != NULL) callbacks->transaction_id = commit->root_prepare->transaction_id;
    if (callbacks->corrupt_plaintext_during_commit != 0u &&
        callbacks->validated_plaintext != NULL &&
        callbacks->validated_plaintext_length != 0u)
        callbacks->validated_plaintext[0] ^= 1u;
    if (callbacks->corrupt_context_during_commit != 0u &&
        callbacks->context_to_corrupt != NULL)
        callbacks->context_to_corrupt->current_epoch ^= 1u;
    return callbacks->result;
}

static uint64_t monotonic_time_us(void *user) {
    callbacks_t *callbacks = (callbacks_t *)user;
    callbacks->monotonic_time_us += 10u;
    return callbacks->monotonic_time_us;
}

static tcsec_status_t init_context(tcsec_context_t *context,
                                   const tcsec_config_t *config,
                                   tcsec_plaintext_validator_fn validator,
                                   void *user_context) {
    const tcsec_callbacks_t callbacks = {
        validator,
        commit_state,
        monotonic_time_us,
        user_context
    };
    return tcsec_init(context, config, &callbacks);
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
    uint8_t tweak[TCSEC_HCTR_TWEAK_LENGTH] = {0};
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
    memcpy(tweak, prefix, TCSEC_NONCE_PREFIX_LENGTH);
    tweak[6] = (uint8_t)(spi >> 8); tweak[7] = (uint8_t)spi;
    tweak[8] = (uint8_t)(iv >> 24); tweak[9] = (uint8_t)(iv >> 16);
    tweak[10] = (uint8_t)(iv >> 8); tweak[11] = (uint8_t)iv;
    if (suite != TCSEC_SUITE_SM4_HCTR || plaintext_length < 16u ||
        tcsec_sm4_hctr_encrypt(key, tweak, plaintext, &frame[11], plaintext_length) != 0)
        return 0;
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
    memset(config->profile_digest, 0x5au, sizeof(config->profile_digest));
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
    return init_context(context, &config, validate_plaintext, callbacks) == TCSEC_OK;
}

static void recovery_config(tcsec_config_t *config, const vector_t *vector) {
    memset(config, 0, sizeof(*config));
    memset(config->profile_digest, 0x5au, sizeof(config->profile_digest));
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
    return init_context(context, &config, validate_plaintext, callbacks) == TCSEC_OK;
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
    return init_context(context, &config, validate_plaintext, callbacks) == TCSEC_OK;
}

static int test_sm4_hctr(void) {
    static const uint8_t working_key[32] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t tweak[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    static const uint8_t plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t expected[16] = {
        0xb7,0xb1,0xdd,0x75,0xf6,0x08,0x01,0x2d,0xc6,0x96,0x21,0xd4,0xea,0x72,0x0a,0x60
    };
    static const uint8_t partial_plaintext[60] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b
    };
    static const uint8_t partial_expected[60] = {
        0xf7,0x50,0x5a,0xff,0x35,0x7a,0xc1,0x31,0x07,0xcd,0xb2,0x84,0x8c,0x6b,0xb2,0xdc,
        0xdd,0xa4,0x73,0xf7,0xa6,0xea,0x93,0x9d,0x44,0xf5,0x2c,0x98,0x6c,0x11,0xca,0x93,
        0x41,0x04,0x2f,0x2b,0x00,0x91,0xa1,0xca,0x5c,0x8f,0x70,0x8c,0xae,0x8c,0xa6,0xa5,
        0xc5,0x9e,0x22,0x28,0xb3,0x61,0x6c,0x44,0x55,0x62,0x77,0x22
    };
    uint8_t output[16];
    uint8_t recovered[16];
    uint8_t partial_output[60];
    uint8_t partial_recovered[60];
    return tcsec_sm4_hctr_encrypt(working_key, tweak, plaintext, output, sizeof(output)) == 0 &&
           memcmp(output, expected, sizeof(output)) == 0 &&
           tcsec_sm4_hctr_decrypt(working_key, tweak, output, recovered, sizeof(recovered)) == 0 &&
           memcmp(recovered, plaintext, sizeof(recovered)) == 0 &&
           tcsec_sm4_hctr_encrypt(working_key, tweak, partial_plaintext, partial_output,
                                  sizeof(partial_output)) == 0 &&
           memcmp(partial_output, partial_expected, sizeof(partial_output)) == 0 &&
           tcsec_sm4_hctr_decrypt(working_key, tweak, partial_output, partial_recovered,
                                  sizeof(partial_recovered)) == 0 &&
           memcmp(partial_recovered, partial_plaintext, sizeof(partial_recovered)) == 0;
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
    static const uint8_t ordinary_expected[32] = {
        0xd0,0x77,0xe6,0x05,0x2e,0x64,0xfa,0x4b,0x35,0xb2,0x46,0x5d,0x32,0x50,0xdc,0xb7,
        0x05,0x5f,0xa7,0x0d,0x4d,0x1d,0xe6,0x80,0x7b,0x5a,0x24,0x97,0xd5,0xc7,0x03,0xe6
    };
    static const uint8_t sm4_root[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    static const uint8_t sm4_expected[16] = {
        0x17,0x35,0x37,0xc6,0x3f,0x1e,0x50,0xad,0x36,0x29,0xcf,0xdc,0x49,0x11,0x8d,0x2b
    };
    uint8_t output[32];
    if (tcsec_derive_ordinary_key(sm4_root, sizeof(sm4_root), 0x1234u,
                                  TCSEC_SUITE_SM4_HCTR, 0x2001u, 7u, 9u,
                                  output, sizeof(output)) != 0 ||
        memcmp(output, ordinary_expected, sizeof(ordinary_expected)) != 0) return 0;
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
    if (tcsec_sm4_hctr_encrypt(NULL, block, block, output, 16u) == 0 ||
        tcsec_sm4_hctr_encrypt(output, NULL, block, output, 16u) == 0 ||
        tcsec_sm4_hctr_encrypt(output, block, block, output, 15u) == 0 ||
        tcsec_sm4_hctr_decrypt(output, block, NULL, output, 16u) == 0)
        return 0;
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
    if (tcsec_derive_ordinary_key(block, 15u, 1u, TCSEC_SUITE_SM4_HCTR,
                                  1u, 1u, 1u, output, sizeof(output)) == 0 ||
        tcsec_derive_ordinary_key(block, 16u, 1u, TCSEC_SUITE_SM4_GCM,
                                  1u, 1u, 1u, output, sizeof(output)) == 0 ||
        tcsec_derive_ordinary_key(block, 16u, 1u, TCSEC_SUITE_SM4_HCTR,
                                  1u, 1u, 1u, output, 31u) == 0 ||
        tcsec_derive_recovery_key(block, 16u, 1u, TCSEC_SUITE_SM4_HCTR,
                                  1u, 1u, output, sizeof(output)) == 0 ||
        tcsec_derive_recovery_key(block, 16u, 1u, TCSEC_SUITE_SM4_GCM,
                                  1u, 1u, output, 15u) == 0)
        return 0;
    for (status = TCSEC_OK; status <= TCSEC_SELF_TEST_FAILED;
         status = (tcsec_status_t)(status + 1))
        if (strcmp(tcsec_status_string(status), "UNKNOWN") == 0) return 0;
    return strcmp(tcsec_status_string((tcsec_status_t)-1), "UNKNOWN") == 0 &&
           strcmp(tcsec_status_string((tcsec_status_t)999), "UNKNOWN") == 0;
}

static int test_strict_configuration(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    tcsec_callbacks_t invalid_callbacks = {validate_plaintext, NULL, monotonic_time_us, &callbacks};
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&config, &vector);
    if (tcsec_init(&context, &config, NULL) != TCSEC_INVALID_ARGUMENT ||
        tcsec_init(&context, &config, &invalid_callbacks) != TCSEC_INVALID_ARGUMENT)
        return 0;
    ordinary_config(&config, &vector);
    config.ordinary.pending_root_present = 1u;
    if (init_context(&context, &config, validate_plaintext, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.pending_root_version = 1u;
    if (init_context(&context, &config, validate_plaintext, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.current_epoch = UINT32_MAX;
    if (init_context(&context, &config, validate_plaintext, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    ordinary_config(&config, &vector);
    config.recovery.spi = (uint16_t)(config.ordinary.current_spi + 1u);
    if (init_context(&context, &config, validate_plaintext, &callbacks) !=
        TCSEC_INVALID_CONFIGURATION) return 0;
    return 1;
}

static int test_context_fault_detection(const char *path) {
    vector_t vector;
    tcsec_context_t context;
    tcsec_result_t result;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector) ||
        !init_ordinary(&context, &vector, &callbacks)) return 0;
    context.current_epoch ^= 1u;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) !=
        TCSEC_STATE_INTEGRITY_FAILED) return 0;
    tcsec_deinit(&context);
    return 1;
}

static int test_runtime_status(const char *path) {
    vector_t vector;
    tcsec_config_t replacement;
    tcsec_context_t context;
    tcsec_result_t result;
    tcsec_runtime_status_t status;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector) || !init_ordinary(&context, &vector, &callbacks) ||
        tcsec_get_runtime_status(&context, &status) != TCSEC_OK ||
        status.self_test != TCSEC_SELF_TEST_PASSED ||
        (status.crypto_backend != TCSEC_CRYPTO_BACKEND_SOFTWARE &&
         status.crypto_backend != TCSEC_CRYPTO_BACKEND_ARMV7_NEON) ||
        status.receive_count != 0u || status.current_spi != vector.spi ||
        status.next_spi != (uint16_t)(vector.spi + 1u) ||
        status.recovery_spi != 0x7002u ||
        memcmp(status.profile_digest, context.profile_digest,
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
    if (tcsec_reset(&context, &replacement) != TCSEC_INVALID_CONFIGURATION)
        return 0;
    tcsec_deinit(&context);
    return tcsec_get_runtime_status(NULL, &status) == TCSEC_INVALID_ARGUMENT &&
           tcsec_get_runtime_status(&context, NULL) == TCSEC_INVALID_ARGUMENT;
}

static int test_reset_transaction(const char *path) {
    vector_t vector;
    tcsec_config_t replacement;
    tcsec_context_t context;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    tcsec_result_t result;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector) ||
        !init_ordinary(&context, &vector, &callbacks)) return 0;

    ordinary_config(&replacement, &vector);
    replacement.ordinary.current_epoch = UINT32_MAX;
    if (tcsec_reset(&context, &replacement) != TCSEC_INVALID_CONFIGURATION ||
        context.initialized == 0u || context.current_spi != vector.spi ||
        context.current_epoch != vector.security_epoch ||
        context.callbacks.validate_plaintext != validate_plaintext ||
        context.callbacks.commit_state != commit_state ||
        context.callbacks.user_context != &callbacks)
        return 0;

    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_OK ||
        callbacks.calls != 1u) return 0;

    ordinary_config(&replacement, &vector);
    if (tcsec_reset(&context, &replacement) != TCSEC_OK ||
        callbacks.calls != 1u || context.current_replay.seen != 0u ||
        context.callbacks.validate_plaintext != validate_plaintext ||
        context.callbacks.commit_state != commit_state ||
        context.callbacks.user_context != &callbacks)
        return 0;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_OK ||
        callbacks.calls != 2u ||
        memcmp(plaintext, vector.plaintext, vector.plaintext_length) != 0)
        return 0;

    tcsec_deinit(&context);
    return tcsec_reset(&context, &replacement) == TCSEC_INVALID_ARGUMENT;
}

static int test_nvm_two_slot_recovery(const char *path) {
    vector_t vector;
    tcsec_nvm_image_t first;
    tcsec_nvm_image_t second;
    tcsec_nvm_image_t decoded;
    tcsec_nvm_repair_plan_t repair;
    tcsec_context_t context;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    tcsec_result_t result;
    uint8_t slot0[TCSEC_NVM_IMAGE_LENGTH];
    uint8_t slot1[TCSEC_NVM_IMAGE_LENGTH];
    uint8_t corrupt[TCSEC_NVM_IMAGE_LENGTH];
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    size_t slot0_length = 0u;
    size_t slot1_length = 0u;
    uint8_t selected = 0xffu;
    if (!load_vector(path, &vector)) return 0;
    memset(&first, 0, sizeof(first));
    first.generation = 7u;
    ordinary_config(&first.config, &vector);
    if (tcsec_nvm_encode(NULL, slot0, sizeof(slot0), &slot0_length) != TCSEC_INVALID_ARGUMENT ||
        tcsec_nvm_encode(&first, NULL, sizeof(slot0), &slot0_length) != TCSEC_INVALID_ARGUMENT ||
        tcsec_nvm_encode(&first, slot0, sizeof(slot0), NULL) != TCSEC_INVALID_ARGUMENT ||
        tcsec_nvm_encode(&first, slot0, sizeof(slot0) - 1u, &slot0_length) != TCSEC_OUTPUT_TOO_SMALL ||
        tcsec_nvm_encode(&first, slot0, sizeof(slot0), &slot0_length) != TCSEC_OK ||
        slot0_length != TCSEC_NVM_IMAGE_LENGTH ||
        tcsec_nvm_decode(NULL, slot0_length, 0u, &decoded) != TCSEC_INVALID_ARGUMENT ||
        tcsec_nvm_decode(slot0, slot0_length, 0u, NULL) != TCSEC_INVALID_ARGUMENT ||
        tcsec_nvm_decode(slot0, slot0_length, 7u, &decoded) != TCSEC_OK ||
        decoded.generation != first.generation ||
        memcmp(decoded.config.profile_digest, first.config.profile_digest,
               sizeof(first.config.profile_digest)) != 0 ||
        decoded.config.ordinary.current_spi != vector.spi ||
        decoded.config.ordinary.root_version != vector.root_version)
        return 0;
    if (init_context(&context, &decoded.config, validate_plaintext, &callbacks) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                      plaintext, sizeof(plaintext), &result) != TCSEC_OK)
        return 0;
    tcsec_deinit(&context);

    if (tcsec_nvm_decode(slot0, slot0_length, 8u, &decoded) != TCSEC_STATE_INTEGRITY_FAILED ||
        tcsec_nvm_decode(slot0, slot0_length - 1u, 0u, &decoded) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    memcpy(corrupt, slot0, sizeof(corrupt)); corrupt[60] ^= 1u;
    if (tcsec_nvm_decode(corrupt, sizeof(corrupt), 0u, &decoded) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    memcpy(corrupt, slot0, sizeof(corrupt)); corrupt[0] ^= 1u;
    if (tcsec_nvm_decode(corrupt, sizeof(corrupt), 0u, &decoded) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;

    second = first;
    second.generation = 8u;
    second.config.ordinary.replay.seen = 1u;
    second.config.ordinary.replay.highest_iv = vector.iv_counter;
    second.config.ordinary.replay.bitmap = 1u;
    if (tcsec_nvm_encode(&second, slot1, sizeof(slot1), &slot1_length) != TCSEC_OK ||
        tcsec_nvm_select_latest(slot0, slot0_length, slot1, slot1_length, 7u,
                                &decoded, &selected) != TCSEC_OK ||
        selected != 1u || decoded.generation != 8u)
        return 0;
    memcpy(corrupt, slot1, sizeof(corrupt)); corrupt[90] ^= 1u;
    if (tcsec_nvm_select_latest(slot0, slot0_length, corrupt, sizeof(corrupt), 7u,
                                &decoded, &selected) != TCSEC_OK ||
        selected != 0u || decoded.generation != 7u)
        return 0;
    if (tcsec_nvm_plan_repair(slot0, slot0_length, corrupt, sizeof(corrupt), 7u,
                              &decoded, &selected, &repair) != TCSEC_OK ||
        repair.required != 1u || repair.target_slot != 1u || repair.generation != 8u ||
        tcsec_nvm_decode(repair.encoded, sizeof(repair.encoded), 8u, &decoded) != TCSEC_OK ||
        decoded.generation != 8u ||
        tcsec_nvm_plan_repair(slot0, slot0_length, slot1, slot1_length, 7u,
                              &decoded, &selected, &repair) != TCSEC_OK || repair.required != 0u ||
        tcsec_nvm_plan_repair(slot0, slot0_length, slot1, slot1_length, 7u,
                              NULL, &selected, &repair) != TCSEC_INVALID_ARGUMENT)
        return 0;
    if (tcsec_nvm_select_latest(corrupt, sizeof(corrupt), corrupt, sizeof(corrupt), 7u,
                                &decoded, &selected) != TCSEC_STATE_INTEGRITY_FAILED ||
        tcsec_nvm_select_latest(slot0, slot0_length, slot1, slot1_length, 0u,
                                NULL, &selected) != TCSEC_INVALID_ARGUMENT ||
        tcsec_nvm_select_latest(slot0, slot0_length, slot1, slot1_length, 0u,
                                &decoded, NULL) != TCSEC_INVALID_ARGUMENT)
        return 0;

    second = first;
    second.config.recovery.root_version++;
    if (tcsec_nvm_encode(&second, slot1, sizeof(slot1), &slot1_length) != TCSEC_OK ||
        tcsec_nvm_select_latest(slot0, slot0_length, slot1, slot1_length, 7u,
                                &decoded, &selected) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    second = first;
    second.generation = 0u;
    if (tcsec_nvm_encode(&second, slot1, sizeof(slot1), &slot1_length) != TCSEC_INVALID_CONFIGURATION)
        return 0;
    second = first;
    memset(second.config.profile_digest, 0, sizeof(second.config.profile_digest));
    if (tcsec_nvm_encode(&second, slot1, sizeof(slot1), &slot1_length) != TCSEC_INVALID_CONFIGURATION)
        return 0;
    second = first;
    second.config.ordinary.pending_root_present = 1u;
    second.config.ordinary.pending_suite = TCSEC_SUITE_SM4_HCTR;
    memcpy(second.config.ordinary.pending_operational_root, vector.root, TCSEC_ROOT_KEY_LENGTH);
    second.config.ordinary.pending_operational_root[0] ^= 1u;
    second.config.ordinary.pending_operational_root_length = TCSEC_ROOT_KEY_LENGTH;
    second.config.ordinary.pending_root_version = vector.root_version + 1u;
    second.config.ordinary.pending_transaction_id = UINT64_C(0x1122334455667788);
    if (tcsec_nvm_encode(&second, slot1, sizeof(slot1), &slot1_length) != TCSEC_OK ||
        tcsec_nvm_decode(slot1, slot1_length, 0u, &decoded) != TCSEC_OK ||
        decoded.config.ordinary.pending_root_present != 1u ||
        decoded.config.ordinary.pending_transaction_id != UINT64_C(0x1122334455667788))
        return 0;
    return 1;
}

static int test_ordinary_vector(const char *path) {
    vector_t vector;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    tcsec_context_t context;
    tcsec_result_t result;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t corrupted[TCSEC_MAX_FRAME_LENGTH];
    uint8_t far_frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_key[TCSEC_HCTR_WORKING_KEY_LENGTH];
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
    tcsec_deinit(&context);
    return 1;
}

static int test_receive_boundaries_and_replay_motion(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    tcsec_result_t result;
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    uint8_t working_key[TCSEC_HCTR_WORKING_KEY_LENGTH];
    size_t frame_length;
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&config, &vector);
    if (init_context(&context, &config, validate_plaintext, &callbacks) != TCSEC_OK)
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
    tcsec_deinit(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_NEW;
    ordinary_config(&config, &vector);
    config.ordinary.replay.highest_iv = 100u;
    config.ordinary.replay.bitmap = 1u;
    config.ordinary.replay.seen = 1u;
    if (init_context(&context, &config, validate_plaintext, &callbacks) != TCSEC_OK ||
        tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, vector.spi, vector.security_epoch,
                                  vector.root_version, working_key,
                                  sizeof(working_key)) != 0 ||
        !build_ordinary_frame(vector.suite, working_key, vector.prefix, vector.spi,
                              200u, vector.plaintext, vector.plaintext_length,
                              frame, &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_OK ||
        !build_ordinary_frame(vector.suite, working_key, vector.prefix, vector.spi,
                              199u, vector.plaintext, vector.plaintext_length,
                              frame, &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_OK ||
        !build_ordinary_frame(vector.suite, working_key, vector.prefix, vector.spi,
                              120u, vector.plaintext, vector.plaintext_length,
                              frame, &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_REPLAY_REJECTED)
        return 0;
    tcsec_deinit(&context);

    ordinary_config(&config, &vector);
    config.ordinary.replay.highest_iv = 100u;
    config.ordinary.replay.bitmap = 1u;
    config.ordinary.replay.seen = 1u;
    if (init_context(&context, &config, validate_plaintext, &callbacks) != TCSEC_OK ||
        !build_ordinary_frame(vector.suite, working_key, vector.prefix, vector.spi,
                              5000u, vector.plaintext, vector.plaintext_length,
                              frame, &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_IV_FORWARD_JUMP_REJECTED)
        return 0;
    tcsec_deinit(&context);
    return 1;
}

static int test_callback_fault_detection(const char *path) {
    vector_t vector;
    tcsec_context_t context;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    tcsec_result_t result;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector)) return 0;

    if (!init_ordinary(&context, &vector, &callbacks)) return 0;
    callbacks.context_to_corrupt = &context;
    callbacks.corrupt_context_during_validation = 1u;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    tcsec_deinit(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_ordinary(&context, &vector, &callbacks)) return 0;
    callbacks.corrupt_plaintext_during_commit = 1u;
    memset(plaintext, 0xa5, sizeof(plaintext));
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED ||
        plaintext[0] != 0u)
        return 0;
    tcsec_deinit(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_ordinary(&context, &vector, &callbacks)) return 0;
    callbacks.context_to_corrupt = &context;
    callbacks.corrupt_context_during_commit = 1u;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    tcsec_deinit(&context);
    return 1;
}

static int test_promotion_failure_paths(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    tcsec_result_t result;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_key[TCSEC_HCTR_WORKING_KEY_LENGTH];
    size_t frame_length;
    if (!load_vector(path, &vector) ||
        tcsec_derive_ordinary_key(vector.root, vector.root_length,
                                  vector.spacecraft_id, vector.suite,
                                  (uint16_t)(vector.spi + 1u),
                                  vector.security_epoch + 1u,
                                  vector.root_version, next_key,
                                  sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix,
                              (uint16_t)(vector.spi + 1u), 1u,
                              vector.plaintext, vector.plaintext_length,
                              frame, &frame_length)) return 0;

    callbacks.result = TCSEC_COMMIT_PERSISTENCE_FAILED;
    if (!init_ordinary(&context, &vector, &callbacks) ||
        tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_PERSISTENCE_FAILED)
        return 0;
    tcsec_deinit(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_ordinary(&context, &vector, &callbacks)) return 0;
    callbacks.corrupt_plaintext_during_commit = 1u;
    if (tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    tcsec_deinit(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_ordinary(&context, &vector, &callbacks)) return 0;
    callbacks.context_to_corrupt = &context;
    callbacks.corrupt_context_during_commit = 1u;
    if (tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    tcsec_deinit(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_NEW;
    ordinary_config(&config, &vector);
    config.ordinary.current_epoch = UINT32_MAX - 1u;
    if (init_context(&context, &config, validate_plaintext, &callbacks) != TCSEC_OK ||
        tcsec_derive_ordinary_key(vector.root, vector.root_length,
                                  vector.spacecraft_id, vector.suite,
                                  (uint16_t)(vector.spi + 1u), UINT32_MAX,
                                  vector.root_version, next_key,
                                  sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix,
                              (uint16_t)(vector.spi + 1u), 1u,
                              vector.plaintext, vector.plaintext_length,
                              frame, &frame_length) ||
        tcsec_receive(&context, frame, frame_length, plaintext,
                      sizeof(plaintext), &result) != TCSEC_INVALID_CONFIGURATION)
        return 0;
    tcsec_deinit(&context);
    return 1;
}

static int test_spi_wrap(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context;
    tcsec_result_t result;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    uint8_t next_key[TCSEC_HCTR_WORKING_KEY_LENGTH];
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    size_t frame_length;
    if (!load_vector(path, &vector)) return 0;
    ordinary_config(&config, &vector);
    config.ordinary.current_spi = UINT16_MAX;
    if (init_context(&context, &config, validate_plaintext, &callbacks) != TCSEC_OK ||
        tcsec_derive_ordinary_key(vector.root, vector.root_length, vector.spacecraft_id,
                                  vector.suite, 0u, vector.security_epoch + 1u,
                                  vector.root_version, next_key, sizeof(next_key)) != 0 ||
        !build_ordinary_frame(vector.suite, next_key, vector.prefix, 0u, 1u,
                              vector.plaintext, vector.plaintext_length,
                              frame, &frame_length)) return 0;
    if (tcsec_receive(&context, frame, frame_length, plaintext, sizeof(plaintext), &result) !=
            TCSEC_EPOCH_PROMOTED || context.current_spi != 0u || result.spi != 0u ||
        memcmp(plaintext, vector.plaintext, vector.plaintext_length) != 0) return 0;
    tcsec_deinit(&context);
    return 1;
}

static int test_recovery_vector(const char *path) {
    vector_t vector;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    tcsec_context_t context;
    tcsec_result_t result;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH];
    uint8_t corrupted[TCSEC_MAX_FRAME_LENGTH];
    uint8_t header_corrupted[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_frame[TCSEC_MAX_FRAME_LENGTH];
    uint8_t next_key[TCSEC_HCTR_WORKING_KEY_LENGTH];
    static const uint8_t command[16] = {
        0xca,0xfe,0x01,0x02,0x03,0x04,0x05,0x06,
        0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e
    };
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
    tcsec_deinit(&restored);
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
    if (status != TCSEC_PERSISTENCE_FAILED || context.recovery_replay.seen != 0u ||
        context.pending_root_present != 0u) return 0;
    tcsec_deinit(&context);
    return 1;
}

static int test_recovery_rejections(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t context;
    callbacks_t callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_REJECTED};
    tcsec_result_t result;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH];
    if (!load_vector(path, &vector) ||
        !init_recovery(&context, &vector, &callbacks)) return 0;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_ROOT_PREPARE_REJECTED)
        return 0;
    tcsec_deinit(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_NEW;
    recovery_config(&config, &vector);
    config.ordinary.root_version++;
    callbacks.result = TCSEC_COMMIT_NEW;
    if (init_context(&context, &config, validate_plaintext, &callbacks) != TCSEC_OK ||
        tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_ROOT_PREPARE_REJECTED)
        return 0;
    tcsec_deinit(&context);

    callbacks.result = (tcsec_commit_result_t)99;
    if (!init_recovery(&context, &vector, &callbacks) ||
        tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_INVALID_CONFIGURATION)
        return 0;
    tcsec_deinit(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_NEW;
    if (!init_recovery(&context, &vector, &callbacks)) return 0;
    callbacks.context_to_corrupt = &context;
    callbacks.corrupt_context_during_commit = 1u;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_STATE_INTEGRITY_FAILED)
        return 0;
    tcsec_deinit(&context);

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.accept_plaintext = 1;
    callbacks.result = TCSEC_COMMIT_NEW;
    recovery_config(&config, &vector);
    config.ordinary.pending_root_present = 1u;
    config.ordinary.pending_suite = TCSEC_SUITE_SM4_HCTR;
    memcpy(config.ordinary.pending_operational_root,
           vector.ordinary_root, TCSEC_ROOT_KEY_LENGTH);
    config.ordinary.pending_operational_root[0] ^= 1u;
    config.ordinary.pending_operational_root_length = TCSEC_ROOT_KEY_LENGTH;
    config.ordinary.pending_root_version = vector.current_root_version + 1u;
    config.ordinary.pending_transaction_id = UINT64_C(0x8877665544332211);
    if (init_context(&context, &config, validate_plaintext, &callbacks) != TCSEC_OK)
        return 0;
    if (tcsec_receive(&context, vector.protected_frame,
                      vector.protected_frame_length, output,
                      sizeof(output), &result) != TCSEC_ROOT_PREPARE_REJECTED)
        return 0;
    tcsec_deinit(&context);
    return 1;
}

static int test_distinct_context_reentrancy(const char *path) {
    vector_t vector;
    tcsec_config_t config;
    tcsec_context_t primary;
    tcsec_context_t secondary;
    callbacks_t secondary_callbacks = {.accept_plaintext = 1, .result = TCSEC_COMMIT_NEW};
    reentrant_callbacks_t primary_callbacks;
    tcsec_result_t primary_result;
    uint8_t primary_plaintext[TCSEC_MAX_FRAME_LENGTH];
    tcsec_status_t primary_status;
    if (!load_vector(path, &vector) ||
        !init_ordinary(&secondary, &vector, &secondary_callbacks)) return 0;
    memset(&primary_callbacks, 0, sizeof(primary_callbacks));
    primary_callbacks.base.accept_plaintext = 1;
    primary_callbacks.base.result = TCSEC_COMMIT_NEW;
    primary_callbacks.secondary_context = &secondary;
    primary_callbacks.frame = vector.protected_frame;
    primary_callbacks.frame_length = vector.protected_frame_length;
    ordinary_config(&config, &vector);
    if (init_context(&primary, &config, validate_plaintext_reentrant,
                     &primary_callbacks) != TCSEC_OK) return 0;
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
    tcsec_deinit(&primary);
    tcsec_deinit(&secondary);
    return 1;
}

int main(int argc, char **argv) {
    int index;
    if (argc != 3) {
        fprintf(stderr, "expected SM4-HCTR ordinary and SM4-GCM recovery vector paths\n");
        return 1;
    }
    if (!test_sm4_hctr()) {
        fprintf(stderr, "SM4-HCTR known-answer test failed\n");
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
    if (!test_nvm_two_slot_recovery(argv[1])) {
        fprintf(stderr, "two-slot NVM recovery tests failed\n");
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
