#ifndef TC_SECURITY_H
#define TC_SECURITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TCSEC_INTERFACE_VERSION 3u
#define TCSEC_PRIMARY_HEADER_LENGTH 5u
#define TCSEC_SECURITY_HEADER_LENGTH 6u
#define TCSEC_FECF_LENGTH 2u
#define TCSEC_MAX_FRAME_LENGTH 1024u
#define TCSEC_SM4_KEY_LENGTH 16u
#define TCSEC_ROOT_KEY_LENGTH 16u
#define TCSEC_HCTR_WORKING_KEY_LENGTH 32u
#define TCSEC_NONCE_PREFIX_LENGTH 6u
#define TCSEC_GCM_NONCE_LENGTH 12u
#define TCSEC_GCM_TAG_LENGTH 16u
#define TCSEC_PROFILE_DIGEST_LENGTH 32u
#define TCSEC_RECEIVE_CYCLE_LIMIT_US 120000u
#define TCSEC_RECOVERY_AAD_LENGTH (TCSEC_PRIMARY_HEADER_LENGTH + TCSEC_SECURITY_HEADER_LENGTH)
#define TCSEC_REPLAY_WINDOW_BITS 64u
#define TCSEC_MAX_FORWARD_JUMP 4096u
#define TCSEC_ROOT_PREPARE_FORMAT_VERSION 1u
#define TCSEC_ROOT_PREPARE_FIXED_LENGTH 25u
#define TCSEC_ROOT_PREPARE_SM4_LENGTH 41u

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
    TCSEC_STATE_INTEGRITY_FAILED,
    TCSEC_EPOCH_PROMOTED,
    TCSEC_ROOT_PREPARED,
    TCSEC_ROOT_ALREADY_PREPARED,
    TCSEC_SELF_TEST_FAILED,
    TCSEC_NOT_INITIALIZED,
    TCSEC_ALREADY_INITIALIZED,
    TCSEC_MISSING_CALLBACK,
    TCSEC_RECEPTION_PAUSED,
    TCSEC_STORAGE_UNAVAILABLE,
    TCSEC_STORAGE_NO_QUORUM,
    TCSEC_STORAGE_ROLLBACK_DETECTED,
    TCSEC_STORAGE_NOT_COMMISSIONED,
    TCSEC_STORAGE_COMMIT_UNCERTAIN,
    TCSEC_STATE_COMMIT_REJECTED,
    TCSEC_CALLBACK_RESULT_INVALID,
    TCSEC_EPOCH_EXHAUSTED,
    TCSEC_SPI_COLLISION,
    TCSEC_KEY_DERIVATION_FAILED,
    TCSEC_PROFILE_MISMATCH
} tcsec_status_t;

typedef enum {
    TCSEC_SUITE_SM4_HCTR = 0x0013,
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
    uint8_t operational_root[TCSEC_ROOT_KEY_LENGTH];
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
    uint8_t pending_operational_root[TCSEC_ROOT_KEY_LENGTH];
    size_t pending_operational_root_length;
    uint32_t pending_root_version;
    uint64_t pending_transaction_id;
} tcsec_ordinary_config_t;

typedef struct {
    tcsec_suite_t suite;
    uint8_t recovery_root[TCSEC_ROOT_KEY_LENGTH];
    size_t recovery_root_length;
    uint32_t root_version;
    uint16_t spi;
    uint8_t nonce_prefix[TCSEC_NONCE_PREFIX_LENGTH];
    tcsec_replay_state_t replay;
} tcsec_recovery_config_t;

typedef struct {
    uint8_t profile_digest[TCSEC_PROFILE_DIGEST_LENGTH];
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
    uint8_t new_operational_root[TCSEC_ROOT_KEY_LENGTH];
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
    TCSEC_COMMIT_PERSISTENCE_FAILED = 3,
    TCSEC_COMMIT_UNCERTAIN = 4
} tcsec_commit_result_t;

/* Flight software atomically persists one logical state change and returns
 * only after verifying it. The core has no storage dependency. The callback
 * must not execute or enqueue ordinary plaintext. root_prepare is non-NULL
 * only for ROOT_PREPARE. The callback must clear its own temporary secrets
 * before returning on every success and failure path. */
typedef tcsec_commit_result_t (*tcsec_state_commit_fn)(void *user_context,
                                                       const tcsec_commit_t *commit);

/* Load one complete, verified durable snapshot into a temporary output.
 * Return TCSEC_OK only after verifying it. The module clears the output
 * after use. Return a storage-specific status for unavailable media, missing
 * quorum, rollback, or an uncommissioned device. Integrity and configuration
 * errors must be reported explicitly. Unexpected return codes are rejected.
 * The callback clears its own temporary secrets before returning on every
 * path, but leaves the output intact. The module clears the output after use. */
typedef tcsec_status_t (*tcsec_state_load_fn)(void *user_context,
                                               tcsec_config_t *config);

typedef uint64_t (*tcsec_monotonic_time_us_fn)(void *user_context);

/* Runtime dependencies supplied by flight software. tcsec_init copies this
 * value; the struct itself need not outlive the call, while user_context and
 * everything it references must remain valid for the running instance. */
typedef struct {
    tcsec_state_load_fn load_state;               /* Required. */
    tcsec_state_commit_fn commit_state;           /* Required. */
    tcsec_monotonic_time_us_fn monotonic_time_us;  /* NULL disables timing. */
    void *user_context;
} tcsec_callbacks_t;

typedef enum {
    TCSEC_SELF_TEST_NOT_RUN = 0,
    TCSEC_SELF_TEST_PASSED = 1,
    TCSEC_SELF_TEST_LOCKED = 2
} tcsec_self_test_state_t;

typedef enum {
    TCSEC_CRYPTO_BACKEND_SOFTWARE = 0,
    TCSEC_CRYPTO_BACKEND_ARMV7_NEON = 1
} tcsec_crypto_backend_t;

typedef struct {
    tcsec_self_test_state_t self_test;
    tcsec_crypto_backend_t crypto_backend;
    uint8_t profile_digest[TCSEC_PROFILE_DIGEST_LENGTH];
    uint16_t current_spi;
    uint16_t next_spi;
    uint16_t recovery_spi;
    uint32_t security_epoch;
    uint32_t root_version;
    uint8_t pending_root_present;
    uint8_t reception_paused;
    tcsec_status_t last_status;
    uint64_t receive_count;
    /* The four timing fields are zero when no clock is configured. */
    uint64_t last_receive_us;
    uint64_t max_receive_us;
    uint64_t cycle_limit_exceeded_count;
    uint64_t clock_anomaly_count;
} tcsec_runtime_status_t;

typedef struct {
    uint16_t spi;
    uint32_t iv_counter;
    uint32_t security_epoch;
    tcsec_profile_t profile;
    tcsec_suite_t suite;
    size_t plaintext_length;
} tcsec_result_t;

/* Caller-owned opaque object. Zero-initialize once at computer startup.
 * Do not inspect, copy, serialize or change its storage. No heap is used. */
#define TCSEC_CONTEXT_STORAGE_SIZE 512u
typedef struct {
    unsigned char _opaque[TCSEC_CONTEXT_STORAGE_SIZE];
} tcsec_context_t;

/* Start with a zero-initialized context. Registers callbacks and loads the
 * initial snapshot. Callback bindings remain fixed until computer restart. */
tcsec_status_t tcsec_init(tcsec_context_t *context,
                          const tcsec_callbacks_t *callbacks);

/* Reloads the complete durable snapshot through the registered callback.
 * A failed reload leaves reception paused. A successful reset resumes it.
 * Serialize reset with receive and every other call on the same context. */
tcsec_status_t tcsec_reset(tcsec_context_t *context);

/* Receives one complete TC transfer frame. Current plaintext is released after
 * durable replay commit; the caller must validate it before execution. Next
 * plaintext additionally passes the built-in mission checks before promotion
 * commits. Root-prepare plaintext is consumed internally.
 *
 * Reentrancy contract: the implementation has no mutable global state, so calls
 * using distinct tcsec_context_t objects may execute concurrently or from nested
 * callbacks. A single context owns one replay/rotation state machine and must be
 * serialized by its caller; callbacks must not re-enter that same context. */
tcsec_status_t tcsec_receive(tcsec_context_t *context,
                             const uint8_t *frame,
                             size_t frame_length,
                             uint8_t *plaintext,
                             size_t plaintext_capacity,
                             tcsec_result_t *result);

/* Returns a semantic, carrier-independent snapshot for housekeeping/AOS
 * publication. It never exposes roots or derived keys. */
tcsec_status_t tcsec_get_runtime_status(const tcsec_context_t *context,
                                        tcsec_runtime_status_t *status);


#ifdef __cplusplus
}
#endif

#endif
