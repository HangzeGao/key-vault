#ifndef TC_SECURITY_H
#define TC_SECURITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TCSEC_PRIMARY_HEADER_LENGTH 5u
#define TCSEC_SECURITY_HEADER_LENGTH 6u
#define TCSEC_FECF_LENGTH 2u
#define TCSEC_MAX_FRAME_LENGTH 1024u
#define TCSEC_SM4_KEY_LENGTH 16u
#define TCSEC_MAX_KEY_LENGTH 32u
#define TCSEC_NONCE_PREFIX_LENGTH 6u
#define TCSEC_GCM_NONCE_LENGTH 12u
#define TCSEC_GCM_TAG_LENGTH 16u
#define TCSEC_REPLAY_WINDOW_BITS 64u
#define TCSEC_MAX_FORWARD_JUMP 4096u
#define TCSEC_ROOT_PREPARE_FORMAT_VERSION 1u
#define TCSEC_ROOT_PREPARE_FIXED_LENGTH 25u
#define TCSEC_ROOT_PREPARE_SM4_LENGTH 41u
#define TCSEC_ROOT_PREPARE_AES_LENGTH 57u

typedef enum {
    TCSEC_OK = 0,
    TCSEC_INVALID_ARGUMENT,
    TCSEC_INVALID_CONFIGURATION,
    TCSEC_FRAME_LENGTH_INVALID,
    TCSEC_FECF_INVALID,
    TCSEC_ASSOCIATION_NOT_FOUND,
    TCSEC_REPLAY_REJECTED,
    TCSEC_IV_FORWARD_JUMP_REJECTED,
    TCSEC_AUTHENTICATION_FAILED,
    TCSEC_OUTPUT_TOO_SMALL,
    TCSEC_PLAINTEXT_REJECTED,
    TCSEC_ROOT_PREPARE_REJECTED,
    TCSEC_PERSISTENCE_FAILED,
    TCSEC_EPOCH_PROMOTED,
    TCSEC_ROOT_PREPARED,
    TCSEC_ROOT_ALREADY_PREPARED
} tcsec_status_t;

typedef enum {
    TCSEC_SUITE_AES_256_CTR = 0x0011,
    TCSEC_SUITE_SM4_CTR = 0x0012,
    TCSEC_SUITE_AES_256_GCM = 0x0001,
    TCSEC_SUITE_SM4_GCM = 0x0002
} tcsec_suite_t;

typedef enum {
    TCSEC_PROFILE_ORDINARY_CURRENT = 1,
    TCSEC_PROFILE_ORDINARY_NEXT = 2,
    TCSEC_PROFILE_ROOT_PREPARE = 3
} tcsec_profile_t;

typedef struct {
    uint32_t highest_iv;
    uint64_t bitmap;
    uint8_t seen;
} tcsec_replay_state_t;

typedef struct {
    uint16_t spacecraft_id;
    tcsec_suite_t suite;
    uint8_t operational_root[TCSEC_MAX_KEY_LENGTH];
    size_t operational_root_length;
    uint32_t root_version;
    uint32_t current_epoch;
    uint16_t current_spi;
    uint8_t nonce_prefix[TCSEC_NONCE_PREFIX_LENGTH];
    tcsec_replay_state_t replay;
    /* Restored durable Root Prepare state. A zero pending_root_present requires
     * every other pending_* field to be zero. */
    uint8_t pending_root_present;
    tcsec_suite_t pending_suite;
    uint8_t pending_operational_root[TCSEC_MAX_KEY_LENGTH];
    size_t pending_operational_root_length;
    uint32_t pending_root_version;
    uint64_t pending_transaction_id;
} tcsec_ordinary_config_t;

typedef struct {
    tcsec_suite_t suite;
    uint8_t recovery_root[TCSEC_MAX_KEY_LENGTH];
    size_t recovery_root_length;
    uint32_t root_version;
    uint16_t spi;
    uint8_t nonce_prefix[TCSEC_NONCE_PREFIX_LENGTH];
    tcsec_replay_state_t replay;
} tcsec_recovery_config_t;

typedef struct {
    tcsec_ordinary_config_t ordinary;
    tcsec_recovery_config_t recovery;
} tcsec_config_t;

typedef struct {
    uint64_t transaction_id;
    uint32_t expected_current_root_version;
    uint32_t new_root_version;
    uint32_t next_security_epoch;
    uint16_t next_spi;
    tcsec_suite_t ordinary_suite;
    uint8_t new_operational_root[TCSEC_MAX_KEY_LENGTH];
    size_t new_operational_root_length;
} tcsec_root_prepare_t;

typedef enum {
    TCSEC_COMMIT_ORDINARY_REPLAY = 1,
    TCSEC_COMMIT_EPOCH_PROMOTION = 2,
    TCSEC_COMMIT_ROOT_PREPARE = 3
} tcsec_commit_kind_t;

typedef struct {
    tcsec_commit_kind_t kind;
    uint16_t spi;
    tcsec_replay_state_t replay;
    uint32_t current_epoch;
    uint32_t root_version;
    tcsec_suite_t suite;
    const tcsec_root_prepare_t *root_prepare;
} tcsec_commit_t;

typedef enum {
    TCSEC_COMMIT_REJECTED = 0,
    TCSEC_COMMIT_NEW = 1,
    TCSEC_COMMIT_ALREADY_APPLIED = 2,
    TCSEC_COMMIT_PERSISTENCE_FAILED = 3
} tcsec_commit_result_t;

typedef int (*tcsec_plaintext_validator_fn)(void *user_context,
                                            const uint8_t primary_header[TCSEC_PRIMARY_HEADER_LENGTH],
                                            const uint8_t *plaintext,
                                            size_t plaintext_length);

/* The adapter atomically persists exactly one commit. It must not execute or
 * enqueue ordinary plaintext. root_prepare is non-NULL only for ROOT_PREPARE. */
typedef tcsec_commit_result_t (*tcsec_state_commit_fn)(void *user_context,
                                                       const tcsec_commit_t *commit);

typedef struct {
    uint16_t spi;
    uint32_t iv_counter;
    uint32_t security_epoch;
    tcsec_profile_t profile;
    tcsec_suite_t suite;
    size_t plaintext_length;
} tcsec_result_t;

/* Caller-owned fixed storage. Fields are implementation-private despite being
 * visible for freestanding-C allocation. */
typedef struct {
    uint16_t spacecraft_id;
    tcsec_suite_t current_suite;
    tcsec_suite_t next_suite;
    tcsec_suite_t recovery_suite;
    uint8_t current_root[TCSEC_MAX_KEY_LENGTH];
    uint8_t pending_root[TCSEC_MAX_KEY_LENGTH];
    uint8_t current_key[TCSEC_MAX_KEY_LENGTH];
    uint8_t next_key[TCSEC_MAX_KEY_LENGTH];
    uint8_t recovery_key[TCSEC_MAX_KEY_LENGTH];
    size_t current_root_length;
    size_t pending_root_length;
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
    tcsec_plaintext_validator_fn validate_plaintext;
    tcsec_state_commit_fn commit_state;
    void *user_context;
    uint8_t initialized;
} tcsec_context_t;

tcsec_status_t tcsec_init(tcsec_context_t *context,
                          const tcsec_config_t *config,
                          tcsec_plaintext_validator_fn validate_plaintext,
                          tcsec_state_commit_fn commit_state,
                          void *user_context);

/* Receives one complete TC transfer frame. Ordinary plaintext is released only
 * after validation and durable replay/promotion commit. Root-prepare plaintext
 * is consumed internally and never copied to the output buffer. */
tcsec_status_t tcsec_receive(tcsec_context_t *context,
                             const uint8_t *frame,
                             size_t frame_length,
                             uint8_t *plaintext,
                             size_t plaintext_capacity,
                             tcsec_result_t *result);

void tcsec_clear(tcsec_context_t *context);
const char *tcsec_status_string(tcsec_status_t status);

#ifdef __cplusplus
}
#endif

#endif
