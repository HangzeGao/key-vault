#include "tc_security.h"
#include "tc_security_kdf.h"
#include "aes256.h"
#include "sm4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VECTOR_BUFFER_SIZE 2048u

typedef struct {
    tcsec_suite_t suite;
    uint8_t key[TCSEC_MAX_KEY_LENGTH];
    size_t key_length;
    uint8_t prefix[6];
    uint16_t spi;
    uint32_t iv_counter;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    size_t plaintext_length;
    uint8_t protected_frame[TCSEC_MAX_FRAME_LENGTH];
    size_t protected_frame_length;
} vector_t;

typedef struct {
    uint32_t persist_calls;
    uint32_t persisted_highest;
    int accept_plaintext;
    int persist_success;
    uint32_t recovery_calls;
    uint64_t transaction_id;
    tcsec_recovery_commit_result_t recovery_result;
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

static int load_vector(const char *path, vector_t *vector) {
    FILE *file = fopen(path, "rb");
    char line[VECTOR_BUFFER_SIZE];
    unsigned fields = 0u;
    if (file == NULL) return 0;
    memset(vector, 0, sizeof(*vector));
    while (fgets(line, sizeof(line), file) != NULL) {
        char *equals;
        char *value;
        size_t length;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        equals = strchr(line, '=');
        if (equals == NULL) { fclose(file); return 0; }
        *equals = '\0';
        value = equals + 1;
        if (strcmp(line, "suite_id") == 0) {
            if (strcmp(value, "AES_256_CTR") == 0) {
                vector->suite = TCSEC_SUITE_AES_256_CTR;
            } else if (strcmp(value, "SM4_CTR") == 0) {
                vector->suite = TCSEC_SUITE_SM4_CTR;
            } else if (strcmp(value, "AES_256_GCM") == 0) {
                vector->suite = TCSEC_SUITE_AES_256_GCM;
            } else if (strcmp(value, "SM4_GCM") == 0) {
                vector->suite = TCSEC_SUITE_SM4_GCM;
            } else {
                goto fail;
            }
            fields |= 1u;
        } else if (strcmp(line, "key") == 0) {
            if (!decode_hex(value, vector->key, sizeof(vector->key), &vector->key_length)) goto fail;
            fields |= 2u;
        } else if (strcmp(line, "nonce_prefix") == 0) {
            if (!decode_hex(value, vector->prefix, sizeof(vector->prefix), &length) || length != 6u) goto fail;
            fields |= 4u;
        } else if (strcmp(line, "spi") == 0) {
            vector->spi = (uint16_t)strtoul(value, NULL, 16); fields |= 8u;
        } else if (strcmp(line, "iv_counter") == 0) {
            vector->iv_counter = (uint32_t)strtoul(value, NULL, 16); fields |= 16u;
        } else if (strcmp(line, "plaintext") == 0) {
            if (!decode_hex(value, vector->plaintext, sizeof(vector->plaintext), &vector->plaintext_length)) goto fail;
            fields |= 32u;
        } else if (strcmp(line, "protected_frame") == 0) {
            if (!decode_hex(value, vector->protected_frame, sizeof(vector->protected_frame), &vector->protected_frame_length)) goto fail;
            fields |= 64u;
        } else {
            goto fail;
        }
    }
    fclose(file);
    return fields == 127u &&
           (((vector->suite == TCSEC_SUITE_AES_256_CTR || vector->suite == TCSEC_SUITE_AES_256_GCM) && vector->key_length == 32u) ||
            ((vector->suite == TCSEC_SUITE_SM4_CTR || vector->suite == TCSEC_SUITE_SM4_GCM) && vector->key_length == 16u));
fail:
    fclose(file);
    return 0;
}

static int validate_plaintext(void *user, const uint8_t *plaintext, size_t length) {
    callbacks_t *callbacks = (callbacks_t *)user;
    return callbacks->accept_plaintext && length >= 2u && plaintext[0] == 0xcau && plaintext[1] == 0xfeu;
}

static int persist_replay(void *user, uint16_t spi, uint32_t highest_iv,
                          uint64_t bitmap, uint8_t seen) {
    callbacks_t *callbacks = (callbacks_t *)user;
    (void)spi;
    (void)bitmap;
    (void)seen;
    callbacks->persist_calls++;
    callbacks->persisted_highest = highest_iv;
    return callbacks->persist_success;
}

static tcsec_recovery_commit_result_t commit_recovery(
    void *user, uint16_t spi, const tcsec_root_recovery_t *transaction,
    uint32_t highest_iv, uint64_t bitmap, uint8_t seen) {
    callbacks_t *callbacks = (callbacks_t *)user;
    (void)spi;
    (void)bitmap;
    (void)seen;
    callbacks->recovery_calls++;
    callbacks->transaction_id = transaction->transaction_id;
    callbacks->persisted_highest = highest_iv;
    return callbacks->recovery_result;
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

static int init_context(tcsec_context_t *context, const vector_t *vector, callbacks_t *callbacks) {
    tcsec_key_config_t key;
    tcsec_sa_config_t association;
    memset(&key, 0, sizeof(key));
    memset(&association, 0, sizeof(association));
    key.slot = 0u;
    key.suite = vector->suite;
    memcpy(key.key, vector->key, vector->key_length);
    association.spi = vector->spi;
    association.key_slot = 0u;
    association.profile = vector->suite == TCSEC_SUITE_AES_256_GCM || vector->suite == TCSEC_SUITE_SM4_GCM
                              ? TCSEC_PROFILE_ROOT_RECOVERY : TCSEC_PROFILE_ORDINARY;
    memcpy(association.nonce_prefix, vector->prefix, sizeof(association.nonce_prefix));
    association.state = TCSEC_SA_ACTIVE;
    return tcsec_init(context, &key, 1u, &association, 1u,
                      validate_plaintext, persist_replay, commit_recovery, callbacks) == TCSEC_OK;
}

static int test_strict_key_configuration(void) {
    tcsec_context_t context;
    tcsec_key_config_t key;
    tcsec_sa_config_t association;
    callbacks_t callbacks = {0};
    callbacks.accept_plaintext = 1;
    callbacks.persist_success = 1;
    memset(&key, 0, sizeof(key));
    memset(&association, 0, sizeof(association));
    key.slot = 0u;
    association.spi = 1u;
    association.key_slot = 0u;
    association.profile = TCSEC_PROFILE_ORDINARY;
    association.state = TCSEC_SA_ACTIVE;
    if (tcsec_init(&context, &key, 1u, &association, 1u,
                   validate_plaintext, persist_replay, NULL, &callbacks) != TCSEC_INVALID_CONFIGURATION) {
        return 0;
    }
    key.suite = TCSEC_SUITE_SM4_CTR;
    key.key[TCSEC_SM4_KEY_LENGTH] = 1u;
    return tcsec_init(&context, &key, 1u, &association, 1u,
                      validate_plaintext, persist_replay, NULL, &callbacks) == TCSEC_INVALID_CONFIGURATION;
}

static int test_interoperability_vector(const char *path) {
    vector_t vector;
    tcsec_context_t context;
    tcsec_result_t result;
    callbacks_t callbacks = {0};
    callbacks.accept_plaintext = 1;
    callbacks.persist_success = 1;
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    uint8_t corrupted[TCSEC_MAX_FRAME_LENGTH];
    tcsec_status_t status;

    if (!load_vector(path, &vector)) {
        fprintf(stderr, "failed to load interoperability vector: %s\n", path);
        return 1;
    }
    if (!init_context(&context, &vector, &callbacks)) {
        fprintf(stderr, "context initialization failed\n");
        return 1;
    }
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           plaintext, sizeof(plaintext), &result);
    if (status != TCSEC_OK || result.spi != vector.spi || result.iv_counter != vector.iv_counter ||
        result.suite != vector.suite || result.profile != TCSEC_PROFILE_ORDINARY ||
        result.plaintext_length != vector.plaintext_length ||
        memcmp(plaintext, vector.plaintext, vector.plaintext_length) != 0 ||
        callbacks.persist_calls != 1u || callbacks.persisted_highest != vector.iv_counter) {
        fprintf(stderr, "ground-to-flight vector failed: %s\n", tcsec_status_string(status));
        return 1;
    }
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           plaintext, sizeof(plaintext), &result);
    if (status != TCSEC_REPLAY_REJECTED || callbacks.persist_calls != 1u) {
        fprintf(stderr, "replay was not rejected\n");
        return 1;
    }
    memcpy(corrupted, vector.protected_frame, vector.protected_frame_length);
    corrupted[vector.protected_frame_length - 1u] ^= 1u;
    if (!init_context(&context, &vector, &callbacks)) return 1;
    status = tcsec_receive(&context, corrupted, vector.protected_frame_length,
                           plaintext, sizeof(plaintext), &result);
    if (status != TCSEC_FECF_INVALID) {
        fprintf(stderr, "invalid FECF accepted\n");
        return 1;
    }
    callbacks.accept_plaintext = 0;
    callbacks.persist_calls = 0u;
    if (!init_context(&context, &vector, &callbacks)) return 1;
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           plaintext, sizeof(plaintext), &result);
    if (status != TCSEC_PLAINTEXT_REJECTED || callbacks.persist_calls != 0u) {
        fprintf(stderr, "rejected plaintext advanced replay state\n");
        return 1;
    }
    callbacks.accept_plaintext = 1;
    callbacks.persist_success = 0;
    callbacks.persist_calls = 0u;
    memset(plaintext, 0xa5, sizeof(plaintext));
    if (!init_context(&context, &vector, &callbacks)) return 1;
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           plaintext, sizeof(plaintext), &result);
    if (status != TCSEC_PERSISTENCE_FAILED || callbacks.persist_calls != 1u || plaintext[0] != 0u) {
        fprintf(stderr, "persistence failure released plaintext or state\n");
        return 1;
    }
    tcsec_clear(&context);
    return 0;
}

static int test_recovery_vector(const char *path) {
    vector_t vector;
    tcsec_context_t context;
    tcsec_result_t result;
    callbacks_t callbacks = {0};
    uint8_t ordinary_output[8];
    uint8_t corrupted[TCSEC_MAX_FRAME_LENGTH];
    uint16_t crc;
    tcsec_status_t status;
    callbacks.accept_plaintext = 1;
    callbacks.persist_success = 1;
    callbacks.recovery_result = TCSEC_RECOVERY_COMMIT_NEW;
    if (!load_vector(path, &vector) || !init_context(&context, &vector, &callbacks)) {
        fprintf(stderr, "failed to initialize recovery vector: %s\n", path);
        return 1;
    }
    memset(ordinary_output, 0xa5, sizeof(ordinary_output));
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           ordinary_output, sizeof(ordinary_output), &result);
    if (status != TCSEC_RECOVERY_COMMITTED || result.profile != TCSEC_PROFILE_ROOT_RECOVERY ||
        result.suite != vector.suite || result.plaintext_length != 0u ||
        callbacks.recovery_calls != 1u || callbacks.transaction_id != 0x0102030405060708ULL ||
        callbacks.persisted_highest != vector.iv_counter || ordinary_output[0] != 0xa5u) {
        fprintf(stderr, "recovery vector failed: %s\n", tcsec_status_string(status));
        return 1;
    }
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           ordinary_output, sizeof(ordinary_output), &result);
    if (status != TCSEC_REPLAY_REJECTED || callbacks.recovery_calls != 1u) {
        fprintf(stderr, "recovery replay was not rejected\n");
        return 1;
    }
    memcpy(corrupted, vector.protected_frame, vector.protected_frame_length);
    corrupted[TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH] ^= 1u;
    crc = frame_crc(corrupted, vector.protected_frame_length - TCSEC_FECF_LENGTH);
    corrupted[vector.protected_frame_length - 2u] = (uint8_t)(crc >> 8);
    corrupted[vector.protected_frame_length - 1u] = (uint8_t)crc;
    callbacks.recovery_calls = 0u;
    if (!init_context(&context, &vector, &callbacks)) return 1;
    status = tcsec_receive(&context, corrupted, vector.protected_frame_length,
                           ordinary_output, sizeof(ordinary_output), &result);
    if (status != TCSEC_AUTHENTICATION_FAILED || callbacks.recovery_calls != 0u) {
        fprintf(stderr, "modified authenticated recovery was accepted: %s\n", tcsec_status_string(status));
        return 1;
    }
    callbacks.recovery_result = TCSEC_RECOVERY_COMMIT_PERSISTENCE_FAILED;
    if (!init_context(&context, &vector, &callbacks)) return 1;
    status = tcsec_receive(&context, vector.protected_frame, vector.protected_frame_length,
                           ordinary_output, sizeof(ordinary_output), &result);
    if (status != TCSEC_PERSISTENCE_FAILED || context.associations[0].replay_seen != 0u) {
        fprintf(stderr, "recovery persistence failure advanced volatile replay state\n");
        return 1;
    }
    tcsec_clear(&context);
    return 0;
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
    if (!test_strict_key_configuration()) {
        fprintf(stderr, "invalid key configuration was accepted\n");
        return 1;
    }
    for (index = 1; index < 3; ++index) {
        if (test_interoperability_vector(argv[index]) != 0) {
            return 1;
        }
    }
    for (index = 3; index < argc; ++index) {
        if (test_recovery_vector(argv[index]) != 0) return 1;
    }
    printf("ordinary CTR and authenticated recovery GCM interoperability tests passed\n");
    return 0;
}
