#ifndef TCSEC_CONTEXT_PRIVATE_H
#define TCSEC_CONTEXT_PRIVATE_H

#include "parameters.h"

typedef struct {
    uint8_t profile_digest[TCSEC_PROFILE_DIGEST_LENGTH];
    uint16_t spacecraft_id;
    uint8_t current_root[TCSEC_ROOT_KEY_LENGTH];
    uint8_t pending_root[TCSEC_ROOT_KEY_LENGTH];
    uint8_t current_key[TCSEC_HCTR_WORKING_KEY_LENGTH];
    uint8_t next_key[TCSEC_HCTR_WORKING_KEY_LENGTH];
    uint8_t recovery_key[TCSEC_SM4_KEY_LENGTH];
    uint32_t current_root_version;
    uint32_t pending_root_version;
    uint64_t pending_transaction_id;
    uint32_t current_epoch;
    uint16_t current_spi;
    uint8_t ordinary_nonce_prefix[TCSEC_NONCE_PREFIX_LENGTH];
    tcsec_replay_state_t current_replay;
    tcsec_replay_state_t next_replay;
    uint8_t pending_root_present;
    uint16_t recovery_spi;
    uint8_t recovery_nonce_prefix[TCSEC_NONCE_PREFIX_LENGTH];
    tcsec_replay_state_t recovery_replay;
    tcsec_callbacks_t callbacks;
    tcsec_status_t last_status;
    uint64_t receive_count;
    uint64_t last_receive_us;
    uint64_t max_receive_us;
    uint64_t cycle_limit_exceeded_count;
    uint64_t clock_anomaly_count;
    tcsec_self_test_state_t self_test_state;
    tcsec_crypto_backend_t crypto_backend;
    uint8_t initialized;
    uint8_t reception_paused;
    uint32_t context_integrity;
    uint32_t context_integrity_inverse;
} tcsec_private_context_t;


_Static_assert(sizeof(tcsec_private_context_t) <= TCSEC_CONTEXT_STORAGE_SIZE,
               "public context storage is too small");

#endif
