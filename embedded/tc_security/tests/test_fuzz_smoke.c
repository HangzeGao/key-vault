#include "tc_security.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t now;
    const tcsec_config_t *config;
} callback_state_t;

static tcsec_status_t load_snapshot(void *user, tcsec_config_t *config) {
    const callback_state_t *state = user;
    *config = *state->config;
    return TCSEC_OK;
}

static tcsec_commit_result_t reject_commit(void *user, const tcsec_commit_t *commit) {
    (void)user;
    (void)commit;
    return TCSEC_COMMIT_REJECTED;
}

static uint64_t monotonic_time(void *user) {
    callback_state_t *state = (callback_state_t *)user;
    state->now++;
    return state->now;
}

static uint32_t next_random(uint32_t *state) {
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

static int decode_hex(const char *text, uint8_t *output, size_t capacity, size_t *length) {
    size_t index;
    size_t text_length = strlen(text);
    if ((text_length & 1u) != 0u || text_length / 2u > capacity) return 0;
    for (index = 0u; index < text_length; index += 2u) {
        unsigned value;
        if (sscanf(&text[index], "%2x", &value) != 1) return 0;
        output[index / 2u] = (uint8_t)value;
    }
    *length = text_length / 2u;
    return 1;
}

static int load_seed_frame(const char *path, uint8_t *frame, size_t *frame_length) {
    FILE *file = fopen(path, "rb");
    char line[4096];
    if (file == NULL) return 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "protected_frame=", 16u) == 0) {
            int result = decode_hex(line + 16u, frame, TCSEC_MAX_FRAME_LENGTH, frame_length);
            fclose(file);
            return result;
        }
    }
    fclose(file);
    return 0;
}

static void make_config(tcsec_config_t *config) {
    static const uint8_t operational_root[TCSEC_ROOT_KEY_LENGTH] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const uint8_t recovery_root[TCSEC_ROOT_KEY_LENGTH] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
    };
    memset(config, 0, sizeof(*config));
    memset(config->profile_digest, 0xa5, sizeof(config->profile_digest));
    config->ordinary.spacecraft_id = 0x23u;
    memcpy(config->ordinary.operational_root, operational_root, sizeof(operational_root));
    config->ordinary.root_version = 1u;
    config->ordinary.current_epoch = 1u;
    config->ordinary.current_spi = 0x1001u;
    memcpy(config->ordinary.nonce_prefix, "ORDNRY", TCSEC_NONCE_PREFIX_LENGTH);
    memcpy(config->recovery.recovery_root, recovery_root, sizeof(recovery_root));
    config->recovery.root_version = 1u;
    config->recovery.spi = 0x7001u;
    memcpy(config->recovery.nonce_prefix, "RECOVR", TCSEC_NONCE_PREFIX_LENGTH);
}

int main(int argc, char **argv) {
    uint8_t seed_frame[TCSEC_MAX_FRAME_LENGTH];
    size_t seed_length;
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH + 1u];
    uint8_t plaintext[TCSEC_MAX_FRAME_LENGTH];
    tcsec_result_t result;
    tcsec_config_t config;
    tcsec_config_t mutated_config;
    tcsec_context_t context = {0};
    callback_state_t callback_state = {.config = &config};
    tcsec_callbacks_t callbacks = {
        .load_state = load_snapshot, .commit_state = reject_commit,
        .monotonic_time_us = monotonic_time, .user_context = &callback_state,
    };
    uint32_t random_state;
    unsigned long iterations;
    unsigned long iteration;
    if (argc != 4 || !load_seed_frame(argv[1], seed_frame, &seed_length)) return 2;
    random_state = (uint32_t)strtoul(argv[2], NULL, 0);
    iterations = strtoul(argv[3], NULL, 10);
    if (random_state == 0u || iterations == 0u) return 2;
    make_config(&config);
    for (iteration = 0u; iteration < iterations; ++iteration) {
        size_t index;
        size_t frame_length = (size_t)(next_random(&random_state) % sizeof(frame));
        memcpy(frame, seed_frame, seed_length);
        for (index = seed_length; index < sizeof(frame); ++index) frame[index] = 0u;
        for (index = 0u; index < 1u + next_random(&random_state) % 16u; ++index) {
            size_t offset = (size_t)(next_random(&random_state) % sizeof(frame));
            frame[offset] ^= (uint8_t)next_random(&random_state);
        }
        mutated_config = config;
        unsigned char *config_bytes = (unsigned char *)&mutated_config;
        size_t offset = (size_t)(next_random(&random_state) % sizeof(mutated_config));
        config_bytes[offset] ^= (unsigned char)(1u << (next_random(&random_state) % 8u));

        if (tcsec_init(&context, &callbacks) != TCSEC_OK) return 4;
        (void)tcsec_receive(&context, frame, frame_length, plaintext,
                            sizeof(plaintext), &result);
        callback_state.config = &mutated_config;
        const tcsec_status_t reload = tcsec_reset(&context);
        if (reload != TCSEC_OK && reload != TCSEC_INVALID_CONFIGURATION && reload != TCSEC_PROFILE_MISMATCH) return 5;
        if (reload != TCSEC_OK &&
            (tcsec_receive(&context, frame, frame_length, plaintext, sizeof(plaintext), &result) !=
                 TCSEC_RECEPTION_PAUSED || result.plaintext_length != 0u))
            return 6;
        callback_state.config = &config;
        memset(&context, 0, sizeof(context));
    }
    printf("smoke fuzz passed: seed=0x%08x iterations=%lu\n",
           (unsigned)strtoul(argv[2], NULL, 0), iterations);
    return 0;
}
