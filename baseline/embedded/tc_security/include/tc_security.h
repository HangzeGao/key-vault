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
#define TCSEC_MAX_KEY_SLOTS 3u
#define TCSEC_MAX_ASSOCIATIONS 4u
#define TCSEC_RECOVERY_FORMAT_VERSION 1u
#define TCSEC_RECOVERY_FIXED_LENGTH 23u
#define TCSEC_RECOVERY_SM4_LENGTH 39u
#define TCSEC_RECOVERY_AES_LENGTH 55u

typedef enum {
    TCSEC_OK = 0,
    TCSEC_INVALID_ARGUMENT,
    TCSEC_INVALID_CONFIGURATION,
    TCSEC_FRAME_LENGTH_INVALID,
    TCSEC_FECF_INVALID,
    TCSEC_ASSOCIATION_NOT_FOUND,
    TCSEC_ASSOCIATION_DISABLED,
    TCSEC_REPLAY_REJECTED,
    TCSEC_AUTHENTICATION_FAILED,
    TCSEC_OUTPUT_TOO_SMALL,
    TCSEC_PLAINTEXT_REJECTED,
    TCSEC_RECOVERY_REJECTED,
    TCSEC_PERSISTENCE_FAILED,
    TCSEC_RECOVERY_COMMITTED,
    TCSEC_RECOVERY_ALREADY_APPLIED
} tcsec_status_t;

typedef enum {
    TCSEC_SA_PREINSTALLED = 0,
    TCSEC_SA_ACTIVE = 1,
    TCSEC_SA_GRACE = 2,
    TCSEC_SA_DISABLED = 3
} tcsec_sa_state_t;

typedef enum {
    TCSEC_SUITE_AES_256_CTR = 0x0011,
    TCSEC_SUITE_SM4_CTR = 0x0012,
    TCSEC_SUITE_AES_256_GCM = 0x0001,
    TCSEC_SUITE_SM4_GCM = 0x0002
} tcsec_suite_t;

typedef enum {
    TCSEC_PROFILE_ORDINARY = 1,
    TCSEC_PROFILE_ROOT_RECOVERY = 2
} tcsec_profile_t;

typedef struct {
    uint8_t slot;
    tcsec_suite_t suite;
    uint8_t key[TCSEC_MAX_KEY_LENGTH];
} tcsec_key_config_t;

typedef struct {
    uint16_t spi;
    uint8_t key_slot;
    tcsec_profile_t profile;
    uint8_t nonce_prefix[TCSEC_NONCE_PREFIX_LENGTH];
    uint32_t highest_iv;
    uint64_t replay_bitmap;
    uint8_t replay_seen;
    tcsec_sa_state_t state;
} tcsec_sa_config_t;

typedef int (*tcsec_plaintext_validator_fn)(void *user,
                                            const uint8_t *plaintext,
                                            size_t plaintext_length);

typedef int (*tcsec_replay_persist_fn)(void *user,
                                      uint16_t spi,
                                      uint32_t highest_iv,
                                      uint64_t replay_bitmap,
                                      uint8_t replay_seen);

typedef struct {
    uint64_t transaction_id;
    uint32_t expected_current_root_version;
    uint32_t new_root_version;
    uint32_t activation_epoch;
    tcsec_suite_t ordinary_suite;
    uint8_t new_operational_root[TCSEC_MAX_KEY_LENGTH];
    size_t new_operational_root_length;
} tcsec_root_recovery_t;

typedef enum {
    TCSEC_RECOVERY_COMMIT_REJECTED = 0,
    TCSEC_RECOVERY_COMMIT_NEW = 1,
    TCSEC_RECOVERY_COMMIT_ALREADY_APPLIED = 2,
    TCSEC_RECOVERY_COMMIT_PERSISTENCE_FAILED = 3
} tcsec_recovery_commit_result_t;

/* This adapter must atomically commit both the typed root transaction and the
 * supplied next replay state. It is the only persistence seam for recovery. */
typedef tcsec_recovery_commit_result_t (*tcsec_recovery_commit_fn)(
    void *user, uint16_t spi, const tcsec_root_recovery_t *transaction,
    uint32_t highest_iv, uint64_t replay_bitmap, uint8_t replay_seen);

typedef struct {
    uint16_t spi;
    uint32_t iv_counter;
    tcsec_profile_t profile;
    tcsec_suite_t suite;
    size_t plaintext_length;
} tcsec_result_t;

/*
 * Context storage is fixed-size and caller-owned. Treat its fields as private;
 * they are public only because freestanding C has no portable opaque stack
 * allocation mechanism.
 */
typedef struct {
    tcsec_key_config_t keys[TCSEC_MAX_KEY_SLOTS];
    tcsec_sa_config_t associations[TCSEC_MAX_ASSOCIATIONS];
    size_t key_count;
    size_t association_count;
    tcsec_plaintext_validator_fn validate_plaintext;
    tcsec_replay_persist_fn persist_replay;
    tcsec_recovery_commit_fn commit_recovery;
    void *callback_user;
    uint8_t initialized;
} tcsec_context_t;

tcsec_status_t tcsec_init(tcsec_context_t *context,
                          const tcsec_key_config_t *keys,
                          size_t key_count,
                          const tcsec_sa_config_t *associations,
                          size_t association_count,
                          tcsec_plaintext_validator_fn validate_plaintext,
                          tcsec_replay_persist_fn persist_replay,
                          tcsec_recovery_commit_fn commit_recovery,
                          void *callback_user);

/*
 * Receives one complete secured TC transfer frame:
 * Ordinary:
 *   primary(5) || SPI(2) || IV_COUNTER(4) || CTR ciphertext || FECF(2)
 * Root recovery:
 *   primary(5) || recovery SPI(2) || IV_COUNTER(4) || GCM ciphertext || TAG(16) || FECF(2)
 *
 * On success, plaintext contains only the recovered original TC data field.
 * No output is released and replay state is not changed on any failure.
 * TCSEC_OK is returned only for ordinary unauthenticated TC. Recovery returns
 * TCSEC_RECOVERY_COMMITTED or TCSEC_RECOVERY_ALREADY_APPLIED and never releases
 * plaintext through the ordinary output buffer.
 */
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
