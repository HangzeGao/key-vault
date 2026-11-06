#include "context_private.h"

#include "gcm.h"
#include "next_validation.h"
#include "sm4.h"
#include "selftest.h"
#include "tc_security_kdf.h"

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

static void context_seal(tcsec_private_context_t *context) {
    context->context_integrity = crc32c(context, offsetof(tcsec_private_context_t, context_integrity));
    context->context_integrity_inverse = ~context->context_integrity;
}

static int context_valid(const tcsec_private_context_t *context) {
    uint32_t expected;
    if (context == NULL || context->initialized != 1u) return 0;
    expected = crc32c(context, offsetof(tcsec_private_context_t, context_integrity));
    if (context->context_integrity != expected ||
        context->context_integrity_inverse != ~expected) return 0;
    return 1;
}

static int context_locked(const tcsec_private_context_t *context) {
    uint32_t expected;
    if (context == NULL || context->self_test_state != TCSEC_SELF_TEST_LOCKED) return 0;
    expected = crc32c(context, offsetof(tcsec_private_context_t, context_integrity));
    return context->context_integrity == expected &&
           context->context_integrity_inverse == ~expected;
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
    if (length != TCSEC_ROOT_PREPARE_SM4_LENGTH) return 0;
    if (plaintext[0] != TCSEC_ROOT_PREPARE_FORMAT_VERSION) return 0;
    memset(transaction, 0, sizeof(*transaction));
    transaction->transaction_id = read_u64_be(&plaintext[1]);
    transaction->expected_current_root_version = read_u32_be(&plaintext[9]);
    transaction->new_root_version = read_u32_be(&plaintext[13]);
    transaction->next_security_epoch = read_u32_be(&plaintext[17]);
    transaction->next_spi = read_u16_be(&plaintext[21]);
    if (transaction->transaction_id == 0u || transaction->expected_current_root_version == 0u ||
        transaction->new_root_version <= transaction->expected_current_root_version ||
        transaction->next_security_epoch == 0u ||
        read_u16_be(&plaintext[23]) != TCSEC_SUITE_SM4_GCM_32)
        return 0;
    memcpy(transaction->new_operational_root, &plaintext[TCSEC_ROOT_PREPARE_FIXED_LENGTH], TCSEC_ROOT_KEY_LENGTH);
    return 1;
}

static tcsec_status_t commit_status(tcsec_commit_result_t result) {
    if (result == TCSEC_COMMIT_PERSISTENCE_FAILED) return TCSEC_PERSISTENCE_FAILED;
    if (result == TCSEC_COMMIT_UNCERTAIN) return TCSEC_STORAGE_COMMIT_UNCERTAIN;
    if (result == TCSEC_COMMIT_REJECTED) return TCSEC_STATE_COMMIT_REJECTED;
    return TCSEC_CALLBACK_RESULT_INVALID;
}

static int pending_config_valid(const tcsec_ordinary_config_t *ordinary) {
    if (ordinary->pending_root_present == 0u) {
        size_t index;
        uint8_t nonzero = 0u;
        for (index = 0u; index < sizeof(ordinary->pending_operational_root); ++index)
            nonzero |= ordinary->pending_operational_root[index];
        return ordinary->pending_root_version == 0u && ordinary->pending_transaction_id == 0u &&
               nonzero == 0u;
    }
    return ordinary->pending_root_present == 1u &&
           ordinary->pending_root_version > ordinary->root_version &&
           ordinary->pending_transaction_id != 0u;
}

static uint16_t next_spi(uint16_t spi) {
    return (uint16_t)(spi + 1u);
}

static int config_valid(const tcsec_config_t *config) {
    const tcsec_ordinary_config_t *ordinary;
    const tcsec_recovery_config_t *recovery;
    uint8_t digest = 0u;
    size_t index;
    if (config == NULL) return 0;
    for (index = 0u; index < TCSEC_PROFILE_DIGEST_LENGTH; ++index)
        digest |= config->profile_digest[index];
    ordinary = &config->ordinary;
    recovery = &config->recovery;
    return digest != 0u && ordinary->spacecraft_id <= 0x03ffu && ordinary->root_version != 0u &&
           ordinary->current_epoch != 0u && ordinary->current_epoch != UINT32_MAX &&
           recovery->root_version != 0u &&
           ordinary->current_auth_used <= TCSEC_ORDINARY_AUTH_LIMIT &&
           ordinary->next_auth_used <= TCSEC_ORDINARY_AUTH_LIMIT &&
           (ordinary->current_auth_used & 1u) == 0u && (ordinary->next_auth_used & 1u) == 0u &&
           (ordinary->replay.seen == 0u || ordinary->current_auth_used >= 2u) &&
           (ordinary->replay.seen == 0u ||
            ordinary->replay.highest_iv <= TCSEC_ORDINARY_COUNTER_MAX) &&
           replay_state_valid(&ordinary->replay) && replay_state_valid(&recovery->replay) &&
           pending_config_valid(ordinary);
}

static int derive_ordinary_hardened(const uint8_t *root, size_t root_length, uint16_t spacecraft_id,
                                    tcsec_suite_t suite, uint16_t spi, uint32_t security_epoch,
                                    uint32_t root_version, uint8_t output[TCSEC_SM4_KEY_LENGTH]) {
    int result =
        tcsec_derive_ordinary_key(root, root_length, spacecraft_id, suite, spi, security_epoch,
                                  root_version, output, TCSEC_SM4_KEY_LENGTH);
    if (result == 0) {
        uint8_t repeated[TCSEC_SM4_KEY_LENGTH];
        int repeated_result = tcsec_derive_ordinary_key(
            root, root_length, spacecraft_id, suite, spi, security_epoch, root_version,
            repeated, sizeof(repeated));
        if (repeated_result != 0 || memcmp(output, repeated, sizeof(repeated)) != 0)
            result = -1;
        zeroize(repeated, sizeof(repeated));
    }
    if (result != 0)
        zeroize(output, TCSEC_SM4_KEY_LENGTH);
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

static tcsec_status_t configure(tcsec_private_context_t *context, const tcsec_config_t *config,
                                 const tcsec_callbacks_t *callbacks) {
    const tcsec_ordinary_config_t *ordinary;
    const tcsec_recovery_config_t *recovery;
    ordinary = &config->ordinary;
    recovery = &config->recovery;
    if (!config_valid(config))
        return TCSEC_INVALID_CONFIGURATION;
    context->spacecraft_id = ordinary->spacecraft_id;
    memcpy(context->current_root, ordinary->operational_root, TCSEC_ROOT_KEY_LENGTH);
    context->current_root_version = ordinary->root_version;
    context->current_epoch = ordinary->current_epoch;
    context->current_spi = ordinary->current_spi;
    memcpy(context->ordinary_nonce_prefix, ordinary->nonce_prefix, TCSEC_NONCE_PREFIX_LENGTH);
    context->current_replay = ordinary->replay;
    context->current_auth_used = ordinary->current_auth_used;
    context->next_auth_used = ordinary->next_auth_used;
    if (ordinary->pending_root_present != 0u) {
        memcpy(context->pending_root, ordinary->pending_operational_root,
               TCSEC_ROOT_KEY_LENGTH);
        context->pending_root_version = ordinary->pending_root_version;
        context->pending_transaction_id = ordinary->pending_transaction_id;
        context->pending_root_present = 1u;
    }
    context->recovery_spi = recovery->spi;
    memcpy(context->recovery_nonce_prefix, recovery->nonce_prefix, TCSEC_NONCE_PREFIX_LENGTH);
    context->recovery_replay = recovery->replay;
    context->callbacks = *callbacks;
    context->self_test_state = TCSEC_SELF_TEST_PASSED;
    if (derive_ordinary_hardened(context->current_root, TCSEC_ROOT_KEY_LENGTH,
                                 context->spacecraft_id, TCSEC_SUITE_SM4_GCM_32,
                                 context->current_spi, context->current_epoch,
                                 context->current_root_version, context->current_key) != 0 ||
        derive_ordinary_hardened(
            context->pending_root_present != 0u ? context->pending_root : context->current_root,
            TCSEC_ROOT_KEY_LENGTH, context->spacecraft_id, TCSEC_SUITE_SM4_GCM_32,
            next_spi(context->current_spi), context->current_epoch + 1u,
            context->pending_root_present != 0u ? context->pending_root_version
                                                : context->current_root_version,
            context->next_key) != 0 ||
        derive_recovery_hardened(recovery->recovery_root, TCSEC_ROOT_KEY_LENGTH,
                                 context->spacecraft_id, TCSEC_SUITE_SM4_GCM, context->recovery_spi,
                                 recovery->root_version, context->recovery_key) != 0)
        return TCSEC_KEY_DERIVATION_FAILED;
    context->initialized = 1u;
    context_seal(context);
    return TCSEC_OK;
}

static tcsec_status_t load_configuration(tcsec_private_context_t *candidate,
                                          const tcsec_private_context_t *previous,
                                          const tcsec_callbacks_t *callbacks) {
    tcsec_config_t config = {0};
    tcsec_status_t status;

    if (tcsec_crypto_self_test(&candidate->crypto_backend) != 0) {
        candidate->self_test_state = TCSEC_SELF_TEST_LOCKED;
        if (previous != NULL)
            memcpy(candidate->profile_digest, previous->profile_digest,
                   TCSEC_PROFILE_DIGEST_LENGTH);
        context_seal(candidate);
        return TCSEC_SELF_TEST_FAILED;
    }

    status = callbacks->load_state(callbacks->user_context, &config);
    if (status != TCSEC_OK && status != TCSEC_INVALID_CONFIGURATION &&
        status != TCSEC_STATE_INTEGRITY_FAILED &&
        status != TCSEC_STORAGE_UNAVAILABLE && status != TCSEC_STORAGE_NO_QUORUM &&
        status != TCSEC_STORAGE_ROLLBACK_DETECTED && status != TCSEC_STORAGE_NOT_COMMISSIONED &&
        status != TCSEC_PERSISTENCE_FAILED)
        status = TCSEC_CALLBACK_RESULT_INVALID;
    if (previous != NULL && !context_valid(previous))
        status = TCSEC_STATE_INTEGRITY_FAILED;
    if (status == TCSEC_OK && previous != NULL &&
        memcmp(previous->profile_digest, config.profile_digest,
               TCSEC_PROFILE_DIGEST_LENGTH) != 0)
        status = TCSEC_PROFILE_MISMATCH;
    if (status == TCSEC_OK) {
        memcpy(candidate->profile_digest, config.profile_digest,
               TCSEC_PROFILE_DIGEST_LENGTH);
        status = configure(candidate, &config, callbacks);
    }
    zeroize(&config, sizeof(config));
    if (status != TCSEC_OK) {
        zeroize(candidate, sizeof(*candidate));
    }
    return status;
}

static tcsec_status_t core_init(tcsec_private_context_t *context,
                          const tcsec_callbacks_t *callbacks) {
    if (context_locked(context)) return TCSEC_SELF_TEST_FAILED;
    if (context == NULL || callbacks == NULL) return TCSEC_INVALID_ARGUMENT;
    if (context->initialized != 0u)
        return context_valid(context) ? TCSEC_ALREADY_INITIALIZED : TCSEC_STATE_INTEGRITY_FAILED;
    if (callbacks->load_state == NULL || callbacks->commit_state == NULL)
        return TCSEC_MISSING_CALLBACK;
    const tcsec_callbacks_t registered = *callbacks;
    memset(context, 0, sizeof(*context));
    return load_configuration(context, NULL, &registered);
}

static void pause_reception(tcsec_private_context_t *context) {
    context->reception_paused = 1u;
    zeroize(context->current_root, sizeof(context->current_root));
    zeroize(context->pending_root, sizeof(context->pending_root));
    zeroize(context->current_key, sizeof(context->current_key));
    zeroize(context->next_key, sizeof(context->next_key));
    zeroize(context->recovery_key, sizeof(context->recovery_key));
}

static tcsec_status_t core_reset(tcsec_private_context_t *context) {
    tcsec_private_context_t candidate = {0};
    tcsec_status_t status;
    if (context_locked(context)) return TCSEC_SELF_TEST_FAILED;
    if (context == NULL) return TCSEC_INVALID_ARGUMENT;
    if (context->initialized == 0u) return TCSEC_NOT_INITIALIZED;
    if (!context_valid(context)) return TCSEC_STATE_INTEGRITY_FAILED;

    const tcsec_callbacks_t callbacks = context->callbacks;
    status = load_configuration(&candidate, context, &callbacks);
    if (status == TCSEC_OK || status == TCSEC_SELF_TEST_FAILED) {
        zeroize(context, sizeof(*context));
        memcpy(context, &candidate, sizeof(*context));
    } else if (context_valid(context)) {
        pause_reception(context);
        context_seal(context);
    }
    context->last_status = status;
    context_seal(context);
    zeroize(&candidate, sizeof(candidate));
    return status;
}

static tcsec_status_t receive_ordinary(tcsec_private_context_t *context, const uint8_t *frame,
                                       size_t frame_length, uint16_t spi, uint32_t iv_counter,
                                       uint8_t candidate_next, uint8_t *plaintext,
                                       size_t plaintext_capacity, tcsec_result_t *result) {
    const uint8_t *key = candidate_next != 0u ? context->next_key : context->current_key;
    const tcsec_suite_t suite = TCSEC_SUITE_SM4_GCM_32;
    tcsec_replay_state_t *state = candidate_next != 0u ? &context->next_replay : &context->current_replay;
    tcsec_replay_state_t next_replay;
    tcsec_commit_t commit;
    tcsec_commit_result_t commit_result;
    uint8_t nonce[TCSEC_GCM_NONCE_LENGTH];
    uint8_t repeated[TCSEC_MAX_FRAME_LENGTH];
    uint32_t *auth_used =
        candidate_next != 0u ? &context->next_auth_used : &context->current_auth_used;
    size_t protected_length = frame_length - TCSEC_PRIMARY_HEADER_LENGTH -
                              TCSEC_SECURITY_HEADER_LENGTH - TCSEC_FECF_LENGTH;
    int replay_result = replay_check_hardened(state, iv_counter, TCSEC_MAX_FORWARD_JUMP);
    uint32_t plaintext_integrity;
    if (replay_result == -1) return TCSEC_REPLAY_REJECTED;
    if (replay_result == -2) return TCSEC_IV_FORWARD_JUMP_REJECTED;
    if (replay_result == -3) return TCSEC_STATE_INTEGRITY_FAILED;
    if (plaintext == NULL || protected_length < 16u)
        return TCSEC_FRAME_LENGTH_INVALID;
    if (protected_length > plaintext_capacity) return TCSEC_OUTPUT_TOO_SMALL;
    if (*auth_used > TCSEC_ORDINARY_AUTH_LIMIT - TCSEC_ORDINARY_VERIFY_COST)
        return TCSEC_AUTH_BUDGET_EXHAUSTED;
    memset(&commit, 0, sizeof(commit));
    commit.kind = TCSEC_COMMIT_AUTH_BUDGET;
    commit.spi = spi;
    commit.current_epoch = context->current_epoch + (candidate_next != 0u ? 1u : 0u);
    commit.root_version = candidate_next != 0u && context->pending_root_present != 0u
                              ? context->pending_root_version
                              : context->current_root_version;
    commit.auth_used = *auth_used + TCSEC_ORDINARY_VERIFY_COST;
    const uint32_t reserved_auth_used = commit.auth_used;
    const uint32_t reservation_integrity = crc32c(&commit, sizeof(commit));
    commit_result = context->callbacks.commit_state(context->callbacks.user_context, &commit);
    if (!context_valid(context) || crc32c(&commit, sizeof(commit)) != reservation_integrity)
        return TCSEC_STATE_INTEGRITY_FAILED;
    if (commit_result != TCSEC_COMMIT_NEW)
        return commit_status(commit_result);
    *auth_used = reserved_auth_used;
    context_seal(context);
    build_gcm_nonce(context->ordinary_nonce_prefix, spi, iv_counter, nonce);
    if (tcsec_gcm_open_short(key, nonce, frame, 7u, &frame[11], protected_length, &frame[7],
                             plaintext) != 0) {
        zeroize(nonce, sizeof(nonce));
        return TCSEC_AUTHENTICATION_FAILED;
    }
    if (tcsec_gcm_open_short(key, nonce, frame, 7u, &frame[11], protected_length, &frame[7],
                             repeated) != 0 ||
        memcmp(plaintext, repeated, protected_length) != 0) {
        zeroize(nonce, sizeof(nonce));
        zeroize(repeated, sizeof(repeated));
        return TCSEC_STATE_INTEGRITY_FAILED;
    }
    zeroize(nonce, sizeof(nonce));
    zeroize(repeated, sizeof(repeated));
    plaintext_integrity = crc32c(plaintext, protected_length);
    if (candidate_next != 0u) {
        int plaintext_valid = tcsec_next_plaintext_allowed(
            context->spacecraft_id, frame, plaintext, protected_length);
        if (!context_valid(context) || plaintext_integrity != crc32c(plaintext, protected_length)) {
            zeroize(plaintext, protected_length);
            return TCSEC_STATE_INTEGRITY_FAILED;
        }
        if (!plaintext_valid) {
            zeroize(plaintext, protected_length);
            return TCSEC_PLAINTEXT_REJECTED;
        }
    }
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
    commit.auth_used = *auth_used;
    if (candidate_next != 0u) {
        const uint8_t *future_root = context->pending_root_present != 0u
                                         ? context->pending_root : context->current_root;
        uint32_t future_root_version = commit.root_version;
        uint8_t future_key[TCSEC_SM4_KEY_LENGTH];
        if (context->current_epoch >= UINT32_MAX - 1u) {
            zeroize(plaintext, protected_length);
            return TCSEC_EPOCH_EXHAUSTED;
        }
        if (derive_ordinary_hardened(
                future_root, TCSEC_ROOT_KEY_LENGTH, context->spacecraft_id, suite,
                next_spi(next_spi(context->current_spi)),
                context->current_epoch + 2u, future_root_version, future_key) != 0) {
            zeroize(plaintext, protected_length);
            return TCSEC_KEY_DERIVATION_FAILED;
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
                       ? TCSEC_PERSISTENCE_FAILED : commit_status(commit_result);
        }
        if (context->pending_root_present != 0u) {
            zeroize(context->current_root, sizeof(context->current_root));
            memcpy(context->current_root, context->pending_root, TCSEC_ROOT_KEY_LENGTH);
            context->current_root_version = context->pending_root_version;
        }
        memcpy(context->current_key, context->next_key, sizeof(context->current_key));
        memcpy(context->next_key, future_key, sizeof(context->next_key));
        zeroize(future_key, sizeof(future_key));
        context->current_epoch++;
        context->current_spi = next_spi(context->current_spi);
        context->current_replay = next_replay;
        context->current_auth_used = context->next_auth_used;
        context->next_auth_used = 0u;
        memset(&context->next_replay, 0, sizeof(context->next_replay));
        zeroize(context->pending_root, sizeof(context->pending_root));
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
                   ? TCSEC_PERSISTENCE_FAILED : commit_status(commit_result);
    }
    context->current_replay = next_replay;
    result->security_epoch = context->current_epoch;
    result->profile = TCSEC_PROFILE_ORDINARY_CURRENT;
    result->plaintext_length = protected_length;
    context_seal(context);
    return TCSEC_OK;
}

static tcsec_status_t receive_root_prepare(tcsec_private_context_t *context, const uint8_t *frame,
                                           size_t frame_length, uint32_t iv_counter,
                                           tcsec_result_t *result) {
    size_t protected_length = frame_length - TCSEC_PRIMARY_HEADER_LENGTH -
                              TCSEC_SECURITY_HEADER_LENGTH - TCSEC_FECF_LENGTH;
    size_t ciphertext_length;
    const uint8_t *ciphertext;
    uint8_t plaintext[TCSEC_ROOT_PREPARE_SM4_LENGTH];
    uint8_t repeated_plaintext[TCSEC_ROOT_PREPARE_SM4_LENGTH];
    uint8_t nonce[TCSEC_GCM_NONCE_LENGTH];
    uint8_t candidate_key[TCSEC_SM4_KEY_LENGTH];
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
    if (tcsec_gcm_open(TCSEC_SUITE_SM4_GCM, context->recovery_key, nonce,
                       frame, TCSEC_RECOVERY_AAD_LENGTH,
                       ciphertext, ciphertext_length, &ciphertext[ciphertext_length], plaintext) != 0) {
        zeroize(nonce, sizeof(nonce));
        zeroize(plaintext, sizeof(plaintext));
        return TCSEC_AUTHENTICATION_FAILED;
    }
    if (tcsec_gcm_open(TCSEC_SUITE_SM4_GCM, context->recovery_key, nonce,
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
    if (context->current_epoch >= UINT32_MAX - 1u) {
        zeroize(plaintext, sizeof(plaintext));
        zeroize(&transaction, sizeof(transaction));
        return TCSEC_EPOCH_EXHAUSTED;
    }
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
         memcmp(context->pending_root, transaction.new_operational_root,
                TCSEC_ROOT_KEY_LENGTH) != 0)) {
        zeroize(plaintext, sizeof(plaintext));
        zeroize(&transaction, sizeof(transaction));
        return TCSEC_ROOT_PREPARE_REJECTED;
    }
    if (derive_ordinary_hardened(transaction.new_operational_root, TCSEC_ROOT_KEY_LENGTH,
                                 context->spacecraft_id, TCSEC_SUITE_SM4_GCM_32,
                                 transaction.next_spi, transaction.next_security_epoch,
                                 transaction.new_root_version, candidate_key) != 0) {
        zeroize(plaintext, sizeof(plaintext));
        zeroize(&transaction, sizeof(transaction));
        return TCSEC_KEY_DERIVATION_FAILED;
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
    if (context->pending_root_present == 0u)
        context->next_auth_used = 0u;
    memcpy(context->pending_root, transaction.new_operational_root,
           TCSEC_ROOT_KEY_LENGTH);
    context->pending_root_version = transaction.new_root_version;
    context->pending_transaction_id = transaction.transaction_id;
    context->pending_root_present = 1u;
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

static tcsec_status_t core_receive(tcsec_private_context_t *context, const uint8_t *frame,
                             size_t frame_length, uint8_t *plaintext,
                             size_t plaintext_capacity, tcsec_result_t *result) {
    uint16_t spi = 0u;
    uint32_t iv_counter = 0u;
    tcsec_status_t status;
    uint64_t start_time = 0u;
    if (context_locked(context)) return TCSEC_SELF_TEST_FAILED;
    if (context == NULL || frame == NULL || result == NULL) return TCSEC_INVALID_ARGUMENT;
    if (context->initialized == 0u) return TCSEC_NOT_INITIALIZED;
    if (!context_valid(context)) return TCSEC_STATE_INTEGRITY_FAILED;
    memset(result, 0, sizeof(*result));
    if (context->reception_paused != 0u) return TCSEC_RECEPTION_PAUSED;
    if (context->callbacks.monotonic_time_us != NULL)
        start_time = context->callbacks.monotonic_time_us(context->callbacks.user_context);
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
    {
        uint16_t control = read_u16_be(&frame[5]);
        uint8_t selector = (uint8_t)(control >> 14);
        if (selector == 3u) {
            if (control != TCSEC_RECOVERY_CONTROL)
                status = TCSEC_FRAME_LENGTH_INVALID;
            else {
                spi = context->recovery_spi;
                iv_counter = read_u32_be(&frame[7]);
                status = receive_root_prepare(context, frame, frame_length, iv_counter, result);
            }
        } else {
            iv_counter = control & TCSEC_ORDINARY_COUNTER_MAX;
            if (selector == context->current_epoch % 3u) {
                spi = context->current_spi;
                status = receive_ordinary(context, frame, frame_length, spi, iv_counter, 0u,
                                          plaintext, plaintext_capacity, result);
            } else if (selector == (context->current_epoch + 1u) % 3u) {
                spi = next_spi(context->current_spi);
                status = receive_ordinary(context, frame, frame_length, spi, iv_counter, 1u,
                                          plaintext, plaintext_capacity, result);
            } else
                status = TCSEC_ASSOCIATION_NOT_FOUND;
        }
    }
    if (status == TCSEC_OK || status == TCSEC_EPOCH_PROMOTED ||
        status == TCSEC_ROOT_PREPARED || status == TCSEC_ROOT_ALREADY_PREPARED) {
        result->spi = spi;
        result->iv_counter = iv_counter;
    }
finish:
    if (!context_valid(context)) return status;
    if (context->callbacks.monotonic_time_us != NULL) {
        uint64_t end_time = context->callbacks.monotonic_time_us(context->callbacks.user_context);
        uint64_t elapsed = 0u;
        if (end_time < start_time) {
            context->clock_anomaly_count++;
        } else {
            elapsed = end_time - start_time;
        }
        context->last_receive_us = elapsed;
        if (elapsed > context->max_receive_us) context->max_receive_us = elapsed;
        if (elapsed > TCSEC_RECEIVE_CYCLE_LIMIT_US) context->cycle_limit_exceeded_count++;
    }
    context->receive_count++;
    context->last_status = status;
    if (status == TCSEC_PERSISTENCE_FAILED || status == TCSEC_STORAGE_COMMIT_UNCERTAIN ||
        status == TCSEC_CALLBACK_RESULT_INVALID || status == TCSEC_STATE_INTEGRITY_FAILED ||
        status == TCSEC_STATE_COMMIT_REJECTED) {
        pause_reception(context);
    }
    context_seal(context);
    return status;
}

static tcsec_status_t core_get_runtime_status(const tcsec_private_context_t *context,
                                        tcsec_runtime_status_t *status) {
    if (context == NULL || status == NULL) return TCSEC_INVALID_ARGUMENT;
    if (context->initialized == 0u && !context_locked(context)) return TCSEC_NOT_INITIALIZED;
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
    status->current_auth_used = context->current_auth_used;
    status->next_auth_used = context->next_auth_used;
    status->reception_paused = context->reception_paused;
    status->last_status = context->last_status;
    status->receive_count = context->receive_count;
    status->last_receive_us = context->last_receive_us;
    status->max_receive_us = context->max_receive_us;
    status->cycle_limit_exceeded_count = context->cycle_limit_exceeded_count;
    status->clock_anomaly_count = context->clock_anomaly_count;
    return context_locked(context) ? TCSEC_SELF_TEST_FAILED : TCSEC_OK;
}

/* memcpy gives the private object its declared type. No cast from opaque byte
 * storage is used, so this also works with strict aliasing and byte alignment. */
static void import_context(tcsec_private_context_t *local, const tcsec_context_t *object) {
    memcpy(local, object->_opaque, sizeof(*local));
}

static void export_context(tcsec_context_t *object, const tcsec_private_context_t *local) {
    zeroize(object, sizeof(*object));
    memcpy(object->_opaque, local, sizeof(*local));
}

tcsec_status_t tcsec_init(tcsec_context_t *context, const tcsec_callbacks_t *callbacks) {
    tcsec_private_context_t local;
    tcsec_status_t status;
    uint32_t before;
    if (context == NULL) return TCSEC_INVALID_ARGUMENT;
    before = crc32c(context, sizeof(*context));
    import_context(&local, context);
    status = core_init(&local, callbacks);
    if (before != crc32c(context, sizeof(*context))) status = TCSEC_STATE_INTEGRITY_FAILED;
    else export_context(context, &local);
    zeroize(&local, sizeof(local));
    return status;
}

tcsec_status_t tcsec_reset(tcsec_context_t *context) {
    tcsec_private_context_t local;
    tcsec_status_t status;
    uint32_t before;
    if (context == NULL) return TCSEC_INVALID_ARGUMENT;
    before = crc32c(context, sizeof(*context));
    import_context(&local, context);
    status = core_reset(&local);
    if (before != crc32c(context, sizeof(*context))) status = TCSEC_STATE_INTEGRITY_FAILED;
    else export_context(context, &local);
    zeroize(&local, sizeof(local));
    return status;
}

tcsec_status_t tcsec_receive(tcsec_context_t *context, const uint8_t *frame,
                             size_t frame_length, uint8_t *plaintext,
                             size_t plaintext_capacity, tcsec_result_t *result) {
    tcsec_private_context_t local;
    tcsec_status_t status;
    uint32_t before;
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (context == NULL) {
        zeroize(plaintext, plaintext_capacity);
        return TCSEC_INVALID_ARGUMENT;
    }
    before = crc32c(context, sizeof(*context));
    import_context(&local, context);
    status = core_receive(&local, frame, frame_length, plaintext, plaintext_capacity, result);
    if (before != crc32c(context, sizeof(*context))) status = TCSEC_STATE_INTEGRITY_FAILED;
    else export_context(context, &local);
    zeroize(&local, sizeof(local));
    if (status != TCSEC_OK && status != TCSEC_EPOCH_PROMOTED) {
        zeroize(plaintext, plaintext_capacity);
        if (result != NULL) result->plaintext_length = 0u;
    }
    return status;
}

tcsec_status_t tcsec_get_runtime_status(const tcsec_context_t *context,
                                        tcsec_runtime_status_t *status) {
    tcsec_private_context_t local;
    tcsec_status_t result;
    if (status != NULL) memset(status, 0, sizeof(*status));
    if (context == NULL || status == NULL) return TCSEC_INVALID_ARGUMENT;
    import_context(&local, context);
    result = core_get_runtime_status(&local, status);
    zeroize(&local, sizeof(local));
    return result;
}
