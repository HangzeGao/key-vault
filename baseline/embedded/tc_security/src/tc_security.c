#include "tc_security.h"

#include "gcm.h"
#include "hctr.h"
#include "sm4.h"
#include "selftest.h"
#include "tc_security_kdf.h"
#include "tc_security_internal.h"

#include <stddef.h>
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
        for (bit = 0u; bit < 8u; ++bit)
            crc = (crc & 0x8000u) != 0u ? (uint16_t)((crc << 1) ^ 0x1021u)
                                         : (uint16_t)(crc << 1);
    }
    return crc;
}

static void zeroize(void *memory, size_t length) {
    volatile uint8_t *cursor = (volatile uint8_t *)memory;
    if (memory == NULL) return;
    while (length-- != 0u) *cursor++ = 0u;
}

static uint32_t crc32c(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = UINT32_MAX;
    size_t index;
    for (index = 0u; index < length; ++index) {
        uint8_t bit;
        crc ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit)
            crc = (crc & 1u) != 0u ? (crc >> 1) ^ UINT32_C(0x82f63b78) : crc >> 1;
    }
    return ~crc;
}

static void context_seal(tcsec_context_t *context) {
    context->context_integrity = crc32c(context, offsetof(tcsec_context_t, context_integrity));
    context->context_integrity_inverse = ~context->context_integrity;
}

static int context_valid(const tcsec_context_t *context) {
    uint32_t expected;
    if (context == NULL || context->initialized != 1u) return 0;
    expected = crc32c(context, offsetof(tcsec_context_t, context_integrity));
    if (context->context_integrity != expected ||
        context->context_integrity_inverse != ~expected) return 0;
    return 1;
}

static int context_locked(const tcsec_context_t *context) {
    uint32_t expected;
    if (context == NULL || context->self_test_state != TCSEC_SELF_TEST_LOCKED) return 0;
    expected = crc32c(context, offsetof(tcsec_context_t, context_integrity));
    return context->context_integrity == expected &&
           context->context_integrity_inverse == ~expected;
}

static int suite_is_ordinary(tcsec_suite_t suite) {
    return suite == TCSEC_SUITE_SM4_HCTR;
}

static int suite_is_gcm(tcsec_suite_t suite) {
    return suite == TCSEC_SUITE_SM4_GCM;
}

static size_t suite_root_length(tcsec_suite_t suite) {
    return suite == TCSEC_SUITE_SM4_HCTR || suite == TCSEC_SUITE_SM4_GCM
               ? TCSEC_SM4_KEY_LENGTH : 0u;
}

static int replay_state_valid(const tcsec_replay_state_t *state) {
    return state != NULL && state->seen <= 1u &&
           ((state->seen == 0u && state->highest_iv == 0u && state->bitmap == 0u) ||
            (state->seen == 1u && (state->bitmap & 1u) != 0u));
}

/* 0=acceptable, -1=replay/stale, -2=forward jump. max_forward=0 disables the cap. */
static int replay_check(const tcsec_replay_state_t *state, uint32_t iv_counter,
                        uint32_t max_forward) {
    uint32_t delta;
    if (state->seen == 0u) return max_forward != 0u && iv_counter > max_forward ? -2 : 0;
    if (iv_counter > state->highest_iv) {
        delta = iv_counter - state->highest_iv;
        return max_forward != 0u && delta > max_forward ? -2 : 0;
    }
    delta = state->highest_iv - iv_counter;
    if (delta >= TCSEC_REPLAY_WINDOW_BITS) return -1;
    return (state->bitmap & ((uint64_t)1u << delta)) != 0u ? -1 : 0;
}

static tcsec_replay_state_t replay_next(const tcsec_replay_state_t *state,
                                        uint32_t iv_counter) {
    tcsec_replay_state_t next = *state;
    if (next.seen == 0u) {
        next.highest_iv = iv_counter;
        next.bitmap = 1u;
        next.seen = 1u;
    } else if (iv_counter > next.highest_iv) {
        uint32_t shift = iv_counter - next.highest_iv;
        next.bitmap = shift >= TCSEC_REPLAY_WINDOW_BITS ? 1u : (next.bitmap << shift) | 1u;
        next.highest_iv = iv_counter;
    } else {
        next.bitmap |= (uint64_t)1u << (next.highest_iv - iv_counter);
    }
    return next;
}

static int replay_check_hardened(const tcsec_replay_state_t *state,
                                 uint32_t iv_counter, uint32_t max_forward) {
    int first = replay_check(state, iv_counter, max_forward);
    volatile uint32_t repeated_iv = iv_counter;
    int second = replay_check(state, repeated_iv, max_forward);
    if (first != second) return -3;
    return first;
}

static int replay_next_hardened(const tcsec_replay_state_t *state,
                                uint32_t iv_counter, tcsec_replay_state_t *next) {
    volatile uint32_t repeated_iv;
    tcsec_replay_state_t repeated;
    *next = replay_next(state, iv_counter);
    repeated_iv = iv_counter;
    repeated = replay_next(state, repeated_iv);
    if (next->highest_iv != repeated.highest_iv ||
        next->bitmap != repeated.bitmap || next->seen != repeated.seen) {
        zeroize(&repeated, sizeof(repeated));
        return -1;
    }
    zeroize(&repeated, sizeof(repeated));
    return 0;
}

static void build_hctr_tweak(const uint8_t prefix[TCSEC_NONCE_PREFIX_LENGTH],
                             uint16_t spi, uint32_t iv_counter,
                             uint8_t tweak[TCSEC_HCTR_TWEAK_LENGTH]) {
    memcpy(tweak, prefix, TCSEC_NONCE_PREFIX_LENGTH);
    tweak[6] = (uint8_t)(spi >> 8);
    tweak[7] = (uint8_t)spi;
    tweak[8] = (uint8_t)(iv_counter >> 24);
    tweak[9] = (uint8_t)(iv_counter >> 16);
    tweak[10] = (uint8_t)(iv_counter >> 8);
    tweak[11] = (uint8_t)iv_counter;
    memset(&tweak[12], 0, 4u);
}

static void build_gcm_nonce(const uint8_t prefix[TCSEC_NONCE_PREFIX_LENGTH],
                            uint16_t spi, uint32_t iv_counter,
                            uint8_t nonce[TCSEC_GCM_NONCE_LENGTH]) {
    memcpy(nonce, prefix, TCSEC_NONCE_PREFIX_LENGTH);
    nonce[6] = (uint8_t)(spi >> 8);
    nonce[7] = (uint8_t)spi;
    nonce[8] = (uint8_t)(iv_counter >> 24);
    nonce[9] = (uint8_t)(iv_counter >> 16);
    nonce[10] = (uint8_t)(iv_counter >> 8);
    nonce[11] = (uint8_t)iv_counter;
}

static int parse_root_prepare(const uint8_t *plaintext, size_t length,
                              tcsec_root_prepare_t *transaction) {
    size_t root_length;
    if (length != TCSEC_ROOT_PREPARE_SM4_LENGTH) return 0;
    if (plaintext[0] != TCSEC_ROOT_PREPARE_FORMAT_VERSION) return 0;
    memset(transaction, 0, sizeof(*transaction));
    transaction->transaction_id = read_u64_be(&plaintext[1]);
    transaction->expected_current_root_version = read_u32_be(&plaintext[9]);
    transaction->new_root_version = read_u32_be(&plaintext[13]);
    transaction->next_security_epoch = read_u32_be(&plaintext[17]);
    transaction->next_spi = read_u16_be(&plaintext[21]);
    transaction->ordinary_suite = (tcsec_suite_t)read_u16_be(&plaintext[23]);
    root_length = length - TCSEC_ROOT_PREPARE_FIXED_LENGTH;
    if (transaction->transaction_id == 0u || transaction->expected_current_root_version == 0u ||
        transaction->new_root_version <= transaction->expected_current_root_version ||
        transaction->next_security_epoch == 0u || !suite_is_ordinary(transaction->ordinary_suite) ||
        root_length != suite_root_length(transaction->ordinary_suite)) return 0;
    memcpy(transaction->new_operational_root, &plaintext[TCSEC_ROOT_PREPARE_FIXED_LENGTH], root_length);
    transaction->new_operational_root_length = root_length;
    return 1;
}

static tcsec_status_t commit_status(tcsec_commit_result_t result) {
    if (result == TCSEC_COMMIT_PERSISTENCE_FAILED) return TCSEC_PERSISTENCE_FAILED;
    if (result == TCSEC_COMMIT_REJECTED) return TCSEC_ROOT_PREPARE_REJECTED;
    return TCSEC_INVALID_CONFIGURATION;
}

static int pending_config_valid(const tcsec_ordinary_config_t *ordinary) {
    if (ordinary->pending_root_present == 0u)
        return ordinary->pending_suite == (tcsec_suite_t)0 &&
               ordinary->pending_operational_root_length == 0u &&
               ordinary->pending_root_version == 0u && ordinary->pending_transaction_id == 0u;
    return ordinary->pending_root_present == 1u && suite_is_ordinary(ordinary->pending_suite) &&
           ordinary->pending_operational_root_length == suite_root_length(ordinary->pending_suite) &&
           ordinary->pending_root_version > ordinary->root_version &&
           ordinary->pending_transaction_id != 0u;
}

static uint16_t next_spi(uint16_t spi) {
    return (uint16_t)(spi + 1u);
}

int tcsec_config_valid_internal(const tcsec_config_t *config) {
    const tcsec_ordinary_config_t *ordinary;
    const tcsec_recovery_config_t *recovery;
    uint8_t digest = 0u;
    size_t index;
    if (config == NULL) return 0;
    for (index = 0u; index < TCSEC_PROFILE_DIGEST_LENGTH; ++index)
        digest |= config->profile_digest[index];
    ordinary = &config->ordinary;
    recovery = &config->recovery;
    return digest != 0u && suite_is_ordinary(ordinary->suite) && suite_is_gcm(recovery->suite) &&
           ordinary->operational_root_length == suite_root_length(ordinary->suite) &&
           recovery->recovery_root_length == suite_root_length(recovery->suite) &&
           ordinary->root_version != 0u && ordinary->current_epoch != 0u &&
           ordinary->current_epoch != UINT32_MAX && recovery->root_version != 0u &&
           next_spi(ordinary->current_spi) != recovery->spi &&
           ordinary->current_spi != recovery->spi && replay_state_valid(&ordinary->replay) &&
           replay_state_valid(&recovery->replay) && pending_config_valid(ordinary);
}

static int derive_ordinary_hardened(const uint8_t *root, size_t root_length,
                                    uint16_t spacecraft_id,
                                    tcsec_suite_t suite, uint16_t spi,
                                    uint32_t security_epoch, uint32_t root_version,
                                    uint8_t output[TCSEC_HCTR_WORKING_KEY_LENGTH]) {
    int result = tcsec_derive_ordinary_key(root, root_length, spacecraft_id, suite, spi,
                                           security_epoch, root_version, output,
                                           TCSEC_HCTR_WORKING_KEY_LENGTH);
    if (result == 0) {
        uint8_t repeated[TCSEC_HCTR_WORKING_KEY_LENGTH];
        int repeated_result = tcsec_derive_ordinary_key(
            root, root_length, spacecraft_id, suite, spi, security_epoch, root_version,
            repeated, sizeof(repeated));
        if (repeated_result != 0 || memcmp(output, repeated, sizeof(repeated)) != 0)
            result = -1;
        zeroize(repeated, sizeof(repeated));
    }
    if (result != 0) zeroize(output, TCSEC_HCTR_WORKING_KEY_LENGTH);
    return result;
}

static int derive_recovery_hardened(const uint8_t *root, size_t root_length,
                                    uint16_t spacecraft_id,
                                    tcsec_suite_t suite, uint16_t spi,
                                    uint32_t root_version,
                                    uint8_t output[TCSEC_SM4_KEY_LENGTH]) {
    int result = tcsec_derive_recovery_key(root, root_length, spacecraft_id, suite, spi,
                                           root_version, output, TCSEC_SM4_KEY_LENGTH);
    if (result == 0) {
        uint8_t repeated[TCSEC_SM4_KEY_LENGTH];
        int repeated_result = tcsec_derive_recovery_key(
            root, root_length, spacecraft_id, suite, spi, root_version,
            repeated, sizeof(repeated));
        if (repeated_result != 0 || memcmp(output, repeated, sizeof(repeated)) != 0)
            result = -1;
        zeroize(repeated, sizeof(repeated));
    }
    if (result != 0) zeroize(output, TCSEC_SM4_KEY_LENGTH);
    return result;
}

tcsec_status_t tcsec_init(tcsec_context_t *context, const tcsec_config_t *config,
                          const tcsec_callbacks_t *callbacks) {
    const tcsec_ordinary_config_t *ordinary;
    const tcsec_recovery_config_t *recovery;
    if (context == NULL || config == NULL || callbacks == NULL ||
        callbacks->validate_plaintext == NULL || callbacks->commit_state == NULL ||
        callbacks->monotonic_time_us == NULL)
        return TCSEC_INVALID_ARGUMENT;
    memset(context, 0, sizeof(*context));
    if (tcsec_crypto_self_test(&context->crypto_backend) != 0) {
        context->self_test_state = TCSEC_SELF_TEST_LOCKED;
        context_seal(context);
        return TCSEC_SELF_TEST_FAILED;
    }
    ordinary = &config->ordinary;
    recovery = &config->recovery;
    if (!tcsec_config_valid_internal(config))
        return TCSEC_INVALID_CONFIGURATION;
    memcpy(context->profile_digest, config->profile_digest, TCSEC_PROFILE_DIGEST_LENGTH);
    context->spacecraft_id = ordinary->spacecraft_id;
    context->current_suite = ordinary->suite;
    context->next_suite = ordinary->pending_root_present != 0u
                              ? ordinary->pending_suite : ordinary->suite;
    context->recovery_suite = recovery->suite;
    memcpy(context->current_root, ordinary->operational_root, ordinary->operational_root_length);
    context->current_root_length = ordinary->operational_root_length;
    context->current_root_version = ordinary->root_version;
    context->current_epoch = ordinary->current_epoch;
    context->current_spi = ordinary->current_spi;
    memcpy(context->ordinary_nonce_prefix, ordinary->nonce_prefix, TCSEC_NONCE_PREFIX_LENGTH);
    context->current_replay = ordinary->replay;
    if (ordinary->pending_root_present != 0u) {
        memcpy(context->pending_root, ordinary->pending_operational_root,
               ordinary->pending_operational_root_length);
        context->pending_root_length = ordinary->pending_operational_root_length;
        context->pending_root_version = ordinary->pending_root_version;
        context->pending_transaction_id = ordinary->pending_transaction_id;
        context->pending_root_present = 1u;
    }
    context->recovery_spi = recovery->spi;
    memcpy(context->recovery_nonce_prefix, recovery->nonce_prefix, TCSEC_NONCE_PREFIX_LENGTH);
    context->recovery_replay = recovery->replay;
    context->callbacks = *callbacks;
    context->self_test_state = TCSEC_SELF_TEST_PASSED;
    if (derive_ordinary_hardened(
            context->current_root, context->current_root_length,
            context->spacecraft_id, context->current_suite, context->current_spi,
            context->current_epoch, context->current_root_version, context->current_key) != 0 ||
        derive_ordinary_hardened(
            context->pending_root_present != 0u ? context->pending_root : context->current_root,
            context->pending_root_present != 0u
                ? context->pending_root_length : context->current_root_length,
            context->spacecraft_id, context->next_suite, next_spi(context->current_spi),
            context->current_epoch + 1u,
            context->pending_root_present != 0u
                ? context->pending_root_version : context->current_root_version,
            context->next_key) != 0 ||
        derive_recovery_hardened(
            recovery->recovery_root, recovery->recovery_root_length, context->spacecraft_id,
            context->recovery_suite, context->recovery_spi, recovery->root_version,
            context->recovery_key) != 0) {
        zeroize(context, sizeof(*context));
        return TCSEC_INVALID_CONFIGURATION;
    }
    context->initialized = 1u;
    context_seal(context);
    return TCSEC_OK;
}

tcsec_status_t tcsec_reset(tcsec_context_t *context,
                           const tcsec_config_t *config) {
    tcsec_context_t candidate;
    tcsec_status_t status;
    if (context == NULL || config == NULL || context->initialized == 0u)
        return context_locked(context) ? TCSEC_SELF_TEST_FAILED : TCSEC_INVALID_ARGUMENT;
    if (!context_valid(context)) return TCSEC_STATE_INTEGRITY_FAILED;
    if (memcmp(context->profile_digest, config->profile_digest,
               TCSEC_PROFILE_DIGEST_LENGTH) != 0)
        return TCSEC_INVALID_CONFIGURATION;
    memset(&candidate, 0, sizeof(candidate));
    status = tcsec_init(&candidate, config, &context->callbacks);
    if (status != TCSEC_OK) {
        zeroize(&candidate, sizeof(candidate));
        return status;
    }
    zeroize(context, sizeof(*context));
    memcpy(context, &candidate, sizeof(*context));
    zeroize(&candidate, sizeof(candidate));
    return TCSEC_OK;
}

static tcsec_status_t receive_ordinary(tcsec_context_t *context, const uint8_t *frame,
                                       size_t frame_length, uint16_t spi, uint32_t iv_counter,
                                       uint8_t candidate_next, uint8_t *plaintext,
                                       size_t plaintext_capacity, tcsec_result_t *result) {
    const uint8_t *key = candidate_next != 0u ? context->next_key : context->current_key;
    tcsec_suite_t suite = candidate_next != 0u ? context->next_suite : context->current_suite;
    tcsec_replay_state_t *state = candidate_next != 0u ? &context->next_replay : &context->current_replay;
    tcsec_replay_state_t next_replay;
    tcsec_commit_t commit;
    tcsec_commit_result_t commit_result;
    uint8_t tweak[TCSEC_HCTR_TWEAK_LENGTH];
    size_t protected_length = frame_length - TCSEC_PRIMARY_HEADER_LENGTH -
                              TCSEC_SECURITY_HEADER_LENGTH - TCSEC_FECF_LENGTH;
    int replay_result = replay_check_hardened(state, iv_counter, TCSEC_MAX_FORWARD_JUMP);
    uint32_t plaintext_integrity;
    if (replay_result == -1) return TCSEC_REPLAY_REJECTED;
    if (replay_result == -2) return TCSEC_IV_FORWARD_JUMP_REJECTED;
    if (replay_result == -3) return TCSEC_STATE_INTEGRITY_FAILED;
    if (plaintext == NULL || protected_length < TCSEC_HCTR_TWEAK_LENGTH)
        return TCSEC_FRAME_LENGTH_INVALID;
    if (protected_length > plaintext_capacity) return TCSEC_OUTPUT_TOO_SMALL;
    build_hctr_tweak(context->ordinary_nonce_prefix, spi, iv_counter, tweak);
    if (suite != TCSEC_SUITE_SM4_HCTR ||
        tcsec_sm4_hctr_decrypt(key, tweak,
                              &frame[TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH],
                              plaintext, protected_length) != 0) {
        zeroize(tweak, sizeof(tweak));
        zeroize(plaintext, protected_length);
        return TCSEC_INVALID_CONFIGURATION;
    }
    zeroize(tweak, sizeof(tweak));
    {
        int plaintext_valid = context->callbacks.validate_plaintext(
            context->callbacks.user_context, frame, plaintext, protected_length);
        if (!context_valid(context)) {
            zeroize(plaintext, protected_length);
            return TCSEC_STATE_INTEGRITY_FAILED;
        }
        if (!plaintext_valid) {
            zeroize(plaintext, protected_length);
            return TCSEC_PLAINTEXT_REJECTED;
        }
    }
    plaintext_integrity = crc32c(plaintext, protected_length);
    if (replay_next_hardened(state, iv_counter, &next_replay) != 0) {
        zeroize(plaintext, protected_length);
        return TCSEC_STATE_INTEGRITY_FAILED;
    }
    memset(&commit, 0, sizeof(commit));
    commit.kind = candidate_next != 0u ? TCSEC_COMMIT_EPOCH_PROMOTION : TCSEC_COMMIT_ORDINARY_REPLAY;
    commit.spi = spi;
    commit.replay = next_replay;
    commit.current_epoch = context->current_epoch + (candidate_next != 0u ? 1u : 0u);
    commit.root_version = candidate_next != 0u && context->pending_root_present != 0u
                              ? context->pending_root_version : context->current_root_version;
    commit.suite = suite;
    if (candidate_next != 0u) {
        const uint8_t *future_root = context->pending_root_present != 0u
                                         ? context->pending_root : context->current_root;
        size_t future_root_length = context->pending_root_present != 0u
                                        ? context->pending_root_length : context->current_root_length;
        uint32_t future_root_version = commit.root_version;
        uint8_t future_key[TCSEC_HCTR_WORKING_KEY_LENGTH];
        if (context->current_epoch >= UINT32_MAX - 1u ||
            derive_ordinary_hardened(
                future_root, future_root_length, context->spacecraft_id, suite,
                next_spi(next_spi(context->current_spi)),
                context->current_epoch + 2u, future_root_version, future_key) != 0) {
            zeroize(plaintext, protected_length);
            return TCSEC_INVALID_CONFIGURATION;
        }
        commit_result = context->callbacks.commit_state(context->callbacks.user_context,
                                                        &commit);
        if (!context_valid(context)) {
            zeroize(future_key, sizeof(future_key));
            zeroize(plaintext, protected_length);
            return TCSEC_STATE_INTEGRITY_FAILED;
        }
        if (plaintext_integrity != crc32c(plaintext, protected_length)) {
            zeroize(future_key, sizeof(future_key));
            zeroize(plaintext, protected_length);
            return TCSEC_STATE_INTEGRITY_FAILED;
        }
        if (commit_result != TCSEC_COMMIT_NEW && commit_result != TCSEC_COMMIT_ALREADY_APPLIED) {
            zeroize(future_key, sizeof(future_key));
            zeroize(plaintext, protected_length);
            return commit_result == TCSEC_COMMIT_PERSISTENCE_FAILED
                       ? TCSEC_PERSISTENCE_FAILED : TCSEC_INVALID_CONFIGURATION;
        }
        if (context->pending_root_present != 0u) {
            zeroize(context->current_root, sizeof(context->current_root));
            memcpy(context->current_root, context->pending_root, context->pending_root_length);
            context->current_root_length = context->pending_root_length;
            context->current_root_version = context->pending_root_version;
        }
        memcpy(context->current_key, context->next_key, sizeof(context->current_key));
        memcpy(context->next_key, future_key, sizeof(context->next_key));
        zeroize(future_key, sizeof(future_key));
        context->current_suite = suite;
        context->next_suite = suite;
        context->current_epoch++;
        context->current_spi = next_spi(context->current_spi);
        context->current_replay = next_replay;
        memset(&context->next_replay, 0, sizeof(context->next_replay));
        zeroize(context->pending_root, sizeof(context->pending_root));
        context->pending_root_length = 0u;
        context->pending_root_version = 0u;
        context->pending_transaction_id = 0u;
        context->pending_root_present = 0u;
        result->security_epoch = context->current_epoch;
        result->profile = TCSEC_PROFILE_ORDINARY_NEXT;
        result->plaintext_length = protected_length;
        context_seal(context);
        return TCSEC_EPOCH_PROMOTED;
    }
    commit_result = context->callbacks.commit_state(context->callbacks.user_context,
                                                    &commit);
    if (!context_valid(context)) {
        zeroize(plaintext, protected_length);
        return TCSEC_STATE_INTEGRITY_FAILED;
    }
    if (plaintext_integrity != crc32c(plaintext, protected_length)) {
        zeroize(plaintext, protected_length);
        return TCSEC_STATE_INTEGRITY_FAILED;
    }
    if (commit_result != TCSEC_COMMIT_NEW) {
        zeroize(plaintext, protected_length);
        return commit_result == TCSEC_COMMIT_PERSISTENCE_FAILED
                   ? TCSEC_PERSISTENCE_FAILED : TCSEC_INVALID_CONFIGURATION;
    }
    context->current_replay = next_replay;
    result->security_epoch = context->current_epoch;
    result->profile = TCSEC_PROFILE_ORDINARY_CURRENT;
    result->plaintext_length = protected_length;
    context_seal(context);
    return TCSEC_OK;
}

static tcsec_status_t receive_root_prepare(tcsec_context_t *context, const uint8_t *frame,
                                           size_t frame_length, uint32_t iv_counter,
                                           tcsec_result_t *result) {
    size_t protected_length = frame_length - TCSEC_PRIMARY_HEADER_LENGTH -
                              TCSEC_SECURITY_HEADER_LENGTH - TCSEC_FECF_LENGTH;
    size_t ciphertext_length;
    const uint8_t *ciphertext;
    uint8_t plaintext[TCSEC_ROOT_PREPARE_SM4_LENGTH];
    uint8_t repeated_plaintext[TCSEC_ROOT_PREPARE_SM4_LENGTH];
    uint8_t nonce[TCSEC_GCM_NONCE_LENGTH];
    uint8_t candidate_key[TCSEC_HCTR_WORKING_KEY_LENGTH];
    tcsec_root_prepare_t transaction;
    tcsec_replay_state_t next_replay;
    tcsec_commit_t commit;
    tcsec_commit_result_t commit_result;
    int replay_result = replay_check_hardened(&context->recovery_replay,
                                              iv_counter, 0u);
    if (replay_result == -3) return TCSEC_STATE_INTEGRITY_FAILED;
    if (replay_result != 0) return TCSEC_REPLAY_REJECTED;
    if (protected_length < TCSEC_GCM_TAG_LENGTH) return TCSEC_FRAME_LENGTH_INVALID;
    ciphertext_length = protected_length - TCSEC_GCM_TAG_LENGTH;
    if (ciphertext_length != TCSEC_ROOT_PREPARE_SM4_LENGTH) return TCSEC_FRAME_LENGTH_INVALID;
    ciphertext = &frame[TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH];
    build_gcm_nonce(context->recovery_nonce_prefix, context->recovery_spi, iv_counter, nonce);
    if (tcsec_gcm_open(context->recovery_suite, context->recovery_key, nonce,
                       frame, TCSEC_RECOVERY_AAD_LENGTH,
                       ciphertext, ciphertext_length, &ciphertext[ciphertext_length], plaintext) != 0) {
        zeroize(nonce, sizeof(nonce));
        zeroize(plaintext, sizeof(plaintext));
        return TCSEC_AUTHENTICATION_FAILED;
    }
    if (tcsec_gcm_open(context->recovery_suite, context->recovery_key, nonce,
                       frame, TCSEC_RECOVERY_AAD_LENGTH,
                       ciphertext, ciphertext_length, &ciphertext[ciphertext_length],
                       repeated_plaintext) != 0 ||
        memcmp(plaintext, repeated_plaintext, ciphertext_length) != 0) {
        zeroize(repeated_plaintext, sizeof(repeated_plaintext));
        zeroize(nonce, sizeof(nonce));
        zeroize(plaintext, sizeof(plaintext));
        return TCSEC_STATE_INTEGRITY_FAILED;
    }
    zeroize(repeated_plaintext, sizeof(repeated_plaintext));
    zeroize(nonce, sizeof(nonce));
    if (!parse_root_prepare(plaintext, ciphertext_length, &transaction) ||
        transaction.expected_current_root_version != context->current_root_version ||
        transaction.next_security_epoch != context->current_epoch + 1u ||
        transaction.next_spi != next_spi(context->current_spi)) {
        zeroize(plaintext, sizeof(plaintext));
        zeroize(&transaction, sizeof(transaction));
        return TCSEC_ROOT_PREPARE_REJECTED;
    }
    if (context->pending_root_present != 0u &&
        (context->pending_transaction_id != transaction.transaction_id ||
         context->pending_root_version != transaction.new_root_version ||
         context->next_suite != transaction.ordinary_suite ||
         context->pending_root_length != transaction.new_operational_root_length ||
         memcmp(context->pending_root, transaction.new_operational_root,
                transaction.new_operational_root_length) != 0)) {
        zeroize(plaintext, sizeof(plaintext));
        zeroize(&transaction, sizeof(transaction));
        return TCSEC_ROOT_PREPARE_REJECTED;
    }
    if (derive_ordinary_hardened(
            transaction.new_operational_root, transaction.new_operational_root_length,
            context->spacecraft_id,
            transaction.ordinary_suite, transaction.next_spi,
            transaction.next_security_epoch, transaction.new_root_version,
            candidate_key) != 0) {
        zeroize(plaintext, sizeof(plaintext));
        zeroize(&transaction, sizeof(transaction));
        return TCSEC_ROOT_PREPARE_REJECTED;
    }
    if (replay_next_hardened(&context->recovery_replay, iv_counter,
                             &next_replay) != 0) {
        zeroize(candidate_key, sizeof(candidate_key));
        zeroize(plaintext, sizeof(plaintext));
        zeroize(&transaction, sizeof(transaction));
        return TCSEC_STATE_INTEGRITY_FAILED;
    }
    memset(&commit, 0, sizeof(commit));
    commit.kind = TCSEC_COMMIT_ROOT_PREPARE;
    commit.spi = context->recovery_spi;
    commit.replay = next_replay;
    commit.current_epoch = context->current_epoch;
    commit.root_version = context->current_root_version;
    commit.suite = context->recovery_suite;
    commit.root_prepare = &transaction;
    commit_result = context->callbacks.commit_state(context->callbacks.user_context,
                                                    &commit);
    if (!context_valid(context)) {
        zeroize(candidate_key, sizeof(candidate_key));
        zeroize(plaintext, sizeof(plaintext));
        zeroize(&transaction, sizeof(transaction));
        return TCSEC_STATE_INTEGRITY_FAILED;
    }
    if (commit_result != TCSEC_COMMIT_NEW && commit_result != TCSEC_COMMIT_ALREADY_APPLIED) {
        zeroize(candidate_key, sizeof(candidate_key));
        zeroize(plaintext, sizeof(plaintext));
        zeroize(&transaction, sizeof(transaction));
        return commit_status(commit_result);
    }
    memcpy(context->pending_root, transaction.new_operational_root,
           transaction.new_operational_root_length);
    context->pending_root_length = transaction.new_operational_root_length;
    context->pending_root_version = transaction.new_root_version;
    context->pending_transaction_id = transaction.transaction_id;
    context->pending_root_present = 1u;
    context->next_suite = transaction.ordinary_suite;
    memcpy(context->next_key, candidate_key, sizeof(context->next_key));
    context->recovery_replay = next_replay;
    zeroize(candidate_key, sizeof(candidate_key));
    zeroize(plaintext, sizeof(plaintext));
    zeroize(&transaction, sizeof(transaction));
    result->profile = TCSEC_PROFILE_ROOT_PREPARE;
    result->security_epoch = context->current_epoch;
    result->plaintext_length = 0u;
    context_seal(context);
    return commit_result == TCSEC_COMMIT_NEW ? TCSEC_ROOT_PREPARED : TCSEC_ROOT_ALREADY_PREPARED;
}

tcsec_status_t tcsec_receive(tcsec_context_t *context, const uint8_t *frame,
                             size_t frame_length, uint8_t *plaintext,
                             size_t plaintext_capacity, tcsec_result_t *result) {
    uint16_t spi;
    uint32_t iv_counter;
    tcsec_status_t status;
    uint64_t start_time;
    uint64_t end_time;
    uint64_t elapsed;
    if (context_locked(context)) return TCSEC_SELF_TEST_FAILED;
    if (context == NULL || frame == NULL || result == NULL || context->initialized == 0u)
        return TCSEC_INVALID_ARGUMENT;
    if (!context_valid(context)) return TCSEC_STATE_INTEGRITY_FAILED;
    start_time = context->callbacks.monotonic_time_us(context->callbacks.user_context);
    memset(result, 0, sizeof(*result));
    if (frame_length < TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH + 1u +
                           TCSEC_FECF_LENGTH || frame_length > TCSEC_MAX_FRAME_LENGTH) {
        status = TCSEC_FRAME_LENGTH_INVALID;
        goto finish;
    }
    if ((size_t)(((uint16_t)(frame[2] & 0x03u) << 8) | frame[3]) + 1u != frame_length)
    {
        status = TCSEC_FRAME_LENGTH_INVALID;
        goto finish;
    }
    if (read_u16_be(&frame[frame_length - TCSEC_FECF_LENGTH]) !=
        crc16_ccitt(frame, frame_length - TCSEC_FECF_LENGTH)) {
        status = TCSEC_FECF_INVALID;
        goto finish;
    }
    spi = read_u16_be(&frame[TCSEC_PRIMARY_HEADER_LENGTH]);
    iv_counter = read_u32_be(&frame[TCSEC_PRIMARY_HEADER_LENGTH + 2u]);
    if (spi == context->current_spi) {
        status = receive_ordinary(context, frame, frame_length, spi, iv_counter, 0u,
                                  plaintext, plaintext_capacity, result);
    } else if (spi == next_spi(context->current_spi)) {
        status = receive_ordinary(context, frame, frame_length, spi, iv_counter, 1u,
                                  plaintext, plaintext_capacity, result);
    } else if (spi == context->recovery_spi) {
        status = receive_root_prepare(context, frame, frame_length, iv_counter, result);
    } else {
        status = TCSEC_ASSOCIATION_NOT_FOUND;
    }
    if (status == TCSEC_OK || status == TCSEC_EPOCH_PROMOTED ||
        status == TCSEC_ROOT_PREPARED || status == TCSEC_ROOT_ALREADY_PREPARED) {
        result->spi = spi;
        result->iv_counter = iv_counter;
        if (result->profile == TCSEC_PROFILE_ROOT_PREPARE) result->suite = context->recovery_suite;
        else if (result->profile == TCSEC_PROFILE_ORDINARY_NEXT) result->suite = context->current_suite;
        else result->suite = context->current_suite;
    }
finish:
    if (!context_valid(context)) return status;
    end_time = context->callbacks.monotonic_time_us(context->callbacks.user_context);
    context->receive_count++;
    if (end_time < start_time) {
        context->clock_anomaly_count++;
        elapsed = 0u;
    } else {
        elapsed = end_time - start_time;
    }
    context->last_receive_us = elapsed;
    if (elapsed > context->max_receive_us) context->max_receive_us = elapsed;
    if (elapsed > TCSEC_RECEIVE_CYCLE_LIMIT_US) context->cycle_limit_exceeded_count++;
    context_seal(context);
    return status;
}

tcsec_status_t tcsec_get_runtime_status(const tcsec_context_t *context,
                                        tcsec_runtime_status_t *status) {
    if (context == NULL || status == NULL) return TCSEC_INVALID_ARGUMENT;
    if (!context_valid(context) && !context_locked(context))
        return TCSEC_STATE_INTEGRITY_FAILED;
    memset(status, 0, sizeof(*status));
    status->self_test = context->self_test_state;
    status->crypto_backend = context->crypto_backend;
    memcpy(status->profile_digest, context->profile_digest, TCSEC_PROFILE_DIGEST_LENGTH);
    status->current_spi = context->current_spi;
    status->next_spi = next_spi(context->current_spi);
    status->recovery_spi = context->recovery_spi;
    status->security_epoch = context->current_epoch;
    status->root_version = context->current_root_version;
    status->pending_root_present = context->pending_root_present;
    status->receive_count = context->receive_count;
    status->last_receive_us = context->last_receive_us;
    status->max_receive_us = context->max_receive_us;
    status->cycle_limit_exceeded_count = context->cycle_limit_exceeded_count;
    status->clock_anomaly_count = context->clock_anomaly_count;
    return context_locked(context) ? TCSEC_SELF_TEST_FAILED : TCSEC_OK;
}

void tcsec_deinit(tcsec_context_t *context) {
    if (context != NULL) zeroize(context, sizeof(*context));
}

const char *tcsec_status_string(tcsec_status_t status) {
    static const char *const names[] = {
        "OK", "INVALID_ARGUMENT", "INVALID_CONFIGURATION", "FRAME_LENGTH_INVALID",
        "FECF_INVALID", "ASSOCIATION_NOT_FOUND", "REPLAY_REJECTED",
        "IV_FORWARD_JUMP_REJECTED", "AUTHENTICATION_FAILED", "OUTPUT_TOO_SMALL",
        "PLAINTEXT_REJECTED", "ROOT_PREPARE_REJECTED", "PERSISTENCE_FAILED",
        "STATE_INTEGRITY_FAILED", "EPOCH_PROMOTED", "ROOT_PREPARED",
        "ROOT_ALREADY_PREPARED", "SELF_TEST_FAILED"
    };
    return (int)status >= 0 && status <= TCSEC_SELF_TEST_FAILED ? names[status] : "UNKNOWN";
}
