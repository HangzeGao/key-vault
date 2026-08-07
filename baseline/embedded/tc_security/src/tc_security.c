#include "tc_security.h"

#include "aes256.h"
#include "gcm.h"
#include "sm4.h"

#include <string.h>

static uint16_t read_u16_be(const uint8_t *value) {
    return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static uint32_t read_u32_be(const uint8_t *value) {
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | (uint32_t)value[3];
}

static uint64_t read_u64_be(const uint8_t *value) {
    uint64_t result = 0u;
    size_t index;
    for (index = 0u; index < 8u; ++index) result = (result << 8) | value[index];
    return result;
}

static uint16_t crc16_ccitt(const uint8_t *data, size_t length) {
    uint16_t crc = 0xffffu;
    size_t index;
    for (index = 0u; index < length; ++index) {
        uint8_t bit;
        crc ^= (uint16_t)data[index] << 8;
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (crc & 0x8000u) != 0u ? (uint16_t)((crc << 1) ^ 0x1021u)
                                         : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static void zeroize(void *memory, size_t length) {
    volatile uint8_t *cursor = (volatile uint8_t *)memory;
    if (memory == NULL) return;
    while (length-- != 0u) *cursor++ = 0u;
}

static tcsec_key_config_t *find_key(tcsec_context_t *context, uint8_t slot) {
    size_t index;
    for (index = 0u; index < context->key_count; ++index) {
        if (context->keys[index].slot == slot) return &context->keys[index];
    }
    return NULL;
}

static tcsec_sa_config_t *find_association(tcsec_context_t *context, uint16_t spi) {
    size_t index;
    for (index = 0u; index < context->association_count; ++index) {
        if (context->associations[index].spi == spi) return &context->associations[index];
    }
    return NULL;
}

static int suite_is_ctr(tcsec_suite_t suite) {
    return suite == TCSEC_SUITE_AES_256_CTR || suite == TCSEC_SUITE_SM4_CTR;
}

static int suite_is_gcm(tcsec_suite_t suite) {
    return suite == TCSEC_SUITE_AES_256_GCM || suite == TCSEC_SUITE_SM4_GCM;
}

static size_t suite_key_length(tcsec_suite_t suite) {
    return suite == TCSEC_SUITE_SM4_CTR || suite == TCSEC_SUITE_SM4_GCM
               ? TCSEC_SM4_KEY_LENGTH : TCSEC_MAX_KEY_LENGTH;
}

static int key_configuration_valid(const tcsec_key_config_t *key) {
    size_t index;
    if (!suite_is_ctr(key->suite) && !suite_is_gcm(key->suite)) return 0;
    for (index = suite_key_length(key->suite); index < TCSEC_MAX_KEY_LENGTH; ++index) {
        if (key->key[index] != 0u) return 0;
    }
    return 1;
}

static int replay_check(const tcsec_sa_config_t *association, uint32_t iv_counter) {
    uint32_t delta;
    if (association->replay_seen == 0u || iv_counter > association->highest_iv) return 0;
    delta = association->highest_iv - iv_counter;
    if (delta >= TCSEC_REPLAY_WINDOW_BITS) return -1;
    return (association->replay_bitmap & ((uint64_t)1u << delta)) != 0u ? -1 : 0;
}

static void replay_next(const tcsec_sa_config_t *association, uint32_t iv_counter,
                        uint32_t *highest_iv, uint64_t *bitmap, uint8_t *seen) {
    *highest_iv = association->highest_iv;
    *bitmap = association->replay_bitmap;
    *seen = association->replay_seen;
    if (*seen == 0u) {
        *highest_iv = iv_counter;
        *bitmap = 1u;
        *seen = 1u;
    } else if (iv_counter > *highest_iv) {
        uint32_t shift = iv_counter - *highest_iv;
        *bitmap = shift >= TCSEC_REPLAY_WINDOW_BITS ? 1u : (*bitmap << shift) | 1u;
        *highest_iv = iv_counter;
    } else {
        *bitmap |= (uint64_t)1u << (*highest_iv - iv_counter);
    }
}

static void build_ctr_counter(const tcsec_sa_config_t *association, uint32_t iv_counter,
                              uint8_t initial_counter[16]) {
    memcpy(initial_counter, association->nonce_prefix, TCSEC_NONCE_PREFIX_LENGTH);
    initial_counter[6] = (uint8_t)(association->spi >> 8);
    initial_counter[7] = (uint8_t)association->spi;
    initial_counter[8] = (uint8_t)(iv_counter >> 24);
    initial_counter[9] = (uint8_t)(iv_counter >> 16);
    initial_counter[10] = (uint8_t)(iv_counter >> 8);
    initial_counter[11] = (uint8_t)iv_counter;
    memset(&initial_counter[12], 0, 4u);
}

static void build_gcm_nonce(const tcsec_sa_config_t *association, uint32_t iv_counter,
                            uint8_t nonce[TCSEC_GCM_NONCE_LENGTH]) {
    memcpy(nonce, association->nonce_prefix, TCSEC_NONCE_PREFIX_LENGTH);
    nonce[6] = (uint8_t)(association->spi >> 8);
    nonce[7] = (uint8_t)association->spi;
    nonce[8] = (uint8_t)(iv_counter >> 24);
    nonce[9] = (uint8_t)(iv_counter >> 16);
    nonce[10] = (uint8_t)(iv_counter >> 8);
    nonce[11] = (uint8_t)iv_counter;
}

static int decrypt_ctr(const tcsec_key_config_t *key, const uint8_t counter[16],
                       const uint8_t *ciphertext, uint8_t *plaintext, size_t length) {
    if (key->suite == TCSEC_SUITE_AES_256_CTR)
        return tcsec_aes256_ctr_xor(key->key, counter, ciphertext, plaintext, length);
    if (key->suite == TCSEC_SUITE_SM4_CTR)
        return tcsec_sm4_ctr_xor(key->key, counter, ciphertext, plaintext, length);
    return -1;
}

static int parse_recovery(const uint8_t *plaintext, size_t length,
                          tcsec_root_recovery_t *transaction) {
    size_t root_length;
    if (length != TCSEC_RECOVERY_SM4_LENGTH && length != TCSEC_RECOVERY_AES_LENGTH) return 0;
    if (plaintext[0] != TCSEC_RECOVERY_FORMAT_VERSION) return 0;
    memset(transaction, 0, sizeof(*transaction));
    transaction->transaction_id = read_u64_be(&plaintext[1]);
    transaction->expected_current_root_version = read_u32_be(&plaintext[9]);
    transaction->new_root_version = read_u32_be(&plaintext[13]);
    transaction->activation_epoch = read_u32_be(&plaintext[17]);
    transaction->ordinary_suite = (tcsec_suite_t)read_u16_be(&plaintext[21]);
    root_length = length - TCSEC_RECOVERY_FIXED_LENGTH;
    if (transaction->transaction_id == 0u || transaction->expected_current_root_version == 0u ||
        transaction->new_root_version <= transaction->expected_current_root_version ||
        transaction->activation_epoch == 0u || !suite_is_ctr(transaction->ordinary_suite) ||
        root_length != suite_key_length(transaction->ordinary_suite)) return 0;
    memcpy(transaction->new_operational_root, &plaintext[TCSEC_RECOVERY_FIXED_LENGTH], root_length);
    transaction->new_operational_root_length = root_length;
    return 1;
}

tcsec_status_t tcsec_init(tcsec_context_t *context, const tcsec_key_config_t *keys,
                          size_t key_count, const tcsec_sa_config_t *associations,
                          size_t association_count, tcsec_plaintext_validator_fn validate_plaintext,
                          tcsec_replay_persist_fn persist_replay,
                          tcsec_recovery_commit_fn commit_recovery, void *callback_user) {
    size_t index;
    size_t compare;
    int ordinary_present = 0;
    int recovery_present = 0;
    if (context == NULL || keys == NULL || associations == NULL || key_count == 0u ||
        key_count > TCSEC_MAX_KEY_SLOTS || association_count == 0u ||
        association_count > TCSEC_MAX_ASSOCIATIONS) return TCSEC_INVALID_ARGUMENT;
    memset(context, 0, sizeof(*context));
    for (index = 0u; index < key_count; ++index) {
        if (keys[index].slot >= TCSEC_MAX_KEY_SLOTS || !key_configuration_valid(&keys[index])) goto invalid;
        for (compare = 0u; compare < index; ++compare)
            if (keys[compare].slot == keys[index].slot) goto invalid;
        context->keys[index] = keys[index];
    }
    context->key_count = key_count;
    for (index = 0u; index < association_count; ++index) {
        tcsec_key_config_t *key = find_key(context, associations[index].key_slot);
        if ((associations[index].state != TCSEC_SA_PREINSTALLED && associations[index].state != TCSEC_SA_ACTIVE &&
             associations[index].state != TCSEC_SA_GRACE && associations[index].state != TCSEC_SA_DISABLED) ||
            (associations[index].replay_seen == 0u && (associations[index].highest_iv != 0u || associations[index].replay_bitmap != 0u)) ||
            (associations[index].replay_seen == 1u && (associations[index].replay_bitmap & 1u) == 0u) ||
            associations[index].replay_seen > 1u || key == NULL) goto invalid;
        if (associations[index].profile == TCSEC_PROFILE_ORDINARY && suite_is_ctr(key->suite)) ordinary_present = 1;
        else if (associations[index].profile == TCSEC_PROFILE_ROOT_RECOVERY && suite_is_gcm(key->suite) &&
                 associations[index].state != TCSEC_SA_GRACE) recovery_present = 1;
        else goto invalid;
        for (compare = 0u; compare < index; ++compare)
            if (associations[compare].spi == associations[index].spi ||
                associations[compare].key_slot == associations[index].key_slot) goto invalid;
        context->associations[index] = associations[index];
    }
    if ((ordinary_present && (validate_plaintext == NULL || persist_replay == NULL)) ||
        (recovery_present && commit_recovery == NULL)) goto invalid;
    context->association_count = association_count;
    context->validate_plaintext = validate_plaintext;
    context->persist_replay = persist_replay;
    context->commit_recovery = commit_recovery;
    context->callback_user = callback_user;
    context->initialized = 1u;
    return TCSEC_OK;
invalid:
    zeroize(context, sizeof(*context));
    return TCSEC_INVALID_CONFIGURATION;
}

tcsec_status_t tcsec_receive(tcsec_context_t *context, const uint8_t *frame, size_t frame_length,
                             uint8_t *plaintext, size_t plaintext_capacity, tcsec_result_t *result) {
    size_t protected_length;
    uint16_t spi;
    uint32_t iv_counter;
    uint32_t next_highest;
    uint64_t next_bitmap;
    uint8_t next_seen;
    tcsec_sa_config_t *association;
    tcsec_key_config_t *key;
    if (context == NULL || !context->initialized || frame == NULL || result == NULL) return TCSEC_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    if (frame_length < TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH + 1u + TCSEC_FECF_LENGTH ||
        frame_length > TCSEC_MAX_FRAME_LENGTH) return TCSEC_FRAME_LENGTH_INVALID;
    if ((size_t)(((uint16_t)(frame[2] & 0x03u) << 8) | frame[3]) + 1u != frame_length)
        return TCSEC_FRAME_LENGTH_INVALID;
    if (read_u16_be(&frame[frame_length - TCSEC_FECF_LENGTH]) !=
        crc16_ccitt(frame, frame_length - TCSEC_FECF_LENGTH)) return TCSEC_FECF_INVALID;
    spi = read_u16_be(&frame[TCSEC_PRIMARY_HEADER_LENGTH]);
    iv_counter = read_u32_be(&frame[TCSEC_PRIMARY_HEADER_LENGTH + 2u]);
    association = find_association(context, spi);
    if (association == NULL) return TCSEC_ASSOCIATION_NOT_FOUND;
    if ((association->profile == TCSEC_PROFILE_ROOT_RECOVERY && association->state != TCSEC_SA_ACTIVE) ||
        (association->profile == TCSEC_PROFILE_ORDINARY && association->state != TCSEC_SA_ACTIVE && association->state != TCSEC_SA_GRACE))
        return TCSEC_ASSOCIATION_DISABLED;
    if (replay_check(association, iv_counter) != 0) return TCSEC_REPLAY_REJECTED;
    key = find_key(context, association->key_slot);
    if (key == NULL) return TCSEC_INVALID_CONFIGURATION;
    replay_next(association, iv_counter, &next_highest, &next_bitmap, &next_seen);
    protected_length = frame_length - TCSEC_PRIMARY_HEADER_LENGTH - TCSEC_SECURITY_HEADER_LENGTH - TCSEC_FECF_LENGTH;
    if (association->profile == TCSEC_PROFILE_ORDINARY) {
        uint8_t counter[16];
        if (plaintext == NULL) return TCSEC_INVALID_ARGUMENT;
        if (protected_length > plaintext_capacity) return TCSEC_OUTPUT_TOO_SMALL;
        build_ctr_counter(association, iv_counter, counter);
        if (decrypt_ctr(key, counter, &frame[TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH], plaintext, protected_length) != 0) {
            zeroize(counter, sizeof(counter));
            zeroize(plaintext, protected_length);
            return TCSEC_INVALID_CONFIGURATION;
        }
        zeroize(counter, sizeof(counter));
        if (!context->validate_plaintext(context->callback_user, plaintext, protected_length)) {
            zeroize(plaintext, protected_length);
            return TCSEC_PLAINTEXT_REJECTED;
        }
        if (!context->persist_replay(context->callback_user, spi, next_highest, next_bitmap, next_seen)) {
            zeroize(plaintext, protected_length);
            return TCSEC_PERSISTENCE_FAILED;
        }
        result->plaintext_length = protected_length;
    } else {
        uint8_t recovery_plaintext[TCSEC_RECOVERY_AES_LENGTH];
        uint8_t nonce[TCSEC_GCM_NONCE_LENGTH];
        tcsec_root_recovery_t transaction;
        tcsec_recovery_commit_result_t commit_result;
        const uint8_t *ciphertext = &frame[TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH];
        size_t ciphertext_length;
        if (protected_length < TCSEC_GCM_TAG_LENGTH) return TCSEC_FRAME_LENGTH_INVALID;
        ciphertext_length = protected_length - TCSEC_GCM_TAG_LENGTH;
        if (ciphertext_length != TCSEC_RECOVERY_SM4_LENGTH && ciphertext_length != TCSEC_RECOVERY_AES_LENGTH)
            return TCSEC_FRAME_LENGTH_INVALID;
        build_gcm_nonce(association, iv_counter, nonce);
        if (tcsec_gcm_open(key->suite, key->key, nonce, frame,
                           TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH,
                           ciphertext, ciphertext_length, &ciphertext[ciphertext_length], recovery_plaintext) != 0) {
            zeroize(nonce, sizeof(nonce));
            zeroize(recovery_plaintext, sizeof(recovery_plaintext));
            return TCSEC_AUTHENTICATION_FAILED;
        }
        zeroize(nonce, sizeof(nonce));
        if (!parse_recovery(recovery_plaintext, ciphertext_length, &transaction)) {
            zeroize(recovery_plaintext, sizeof(recovery_plaintext));
            return TCSEC_RECOVERY_REJECTED;
        }
        commit_result = context->commit_recovery(context->callback_user, spi, &transaction,
                                                  next_highest, next_bitmap, next_seen);
        zeroize(&transaction, sizeof(transaction));
        zeroize(recovery_plaintext, sizeof(recovery_plaintext));
        if (commit_result == TCSEC_RECOVERY_COMMIT_REJECTED) return TCSEC_RECOVERY_REJECTED;
        if (commit_result == TCSEC_RECOVERY_COMMIT_PERSISTENCE_FAILED) return TCSEC_PERSISTENCE_FAILED;
        if (commit_result != TCSEC_RECOVERY_COMMIT_NEW &&
            commit_result != TCSEC_RECOVERY_COMMIT_ALREADY_APPLIED) return TCSEC_INVALID_CONFIGURATION;
        result->plaintext_length = 0u;
        association->highest_iv = next_highest;
        association->replay_bitmap = next_bitmap;
        association->replay_seen = next_seen;
        result->spi = spi;
        result->iv_counter = iv_counter;
        result->profile = association->profile;
        result->suite = key->suite;
        return commit_result == TCSEC_RECOVERY_COMMIT_NEW ? TCSEC_RECOVERY_COMMITTED : TCSEC_RECOVERY_ALREADY_APPLIED;
    }
    association->highest_iv = next_highest;
    association->replay_bitmap = next_bitmap;
    association->replay_seen = next_seen;
    result->spi = spi;
    result->iv_counter = iv_counter;
    result->profile = association->profile;
    result->suite = key->suite;
    return TCSEC_OK;
}

void tcsec_clear(tcsec_context_t *context) {
    if (context != NULL) zeroize(context, sizeof(*context));
}

const char *tcsec_status_string(tcsec_status_t status) {
    static const char *const names[] = {
        "OK", "INVALID_ARGUMENT", "INVALID_CONFIGURATION", "FRAME_LENGTH_INVALID",
        "FECF_INVALID", "ASSOCIATION_NOT_FOUND", "ASSOCIATION_DISABLED", "REPLAY_REJECTED",
        "AUTHENTICATION_FAILED", "OUTPUT_TOO_SMALL", "PLAINTEXT_REJECTED", "RECOVERY_REJECTED",
        "PERSISTENCE_FAILED", "RECOVERY_COMMITTED", "RECOVERY_ALREADY_APPLIED"
    };
    return (int)status >= 0 && status <= TCSEC_RECOVERY_ALREADY_APPLIED ? names[status] : "UNKNOWN";
}
