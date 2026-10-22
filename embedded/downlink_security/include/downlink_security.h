#ifndef DOWNLINK_SECURITY_H
#define DOWNLINK_SECURITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DLSEC_KEY_LENGTH 32u
#define DLSEC_DATA_LENGTH 880u

typedef enum {
    DLSEC_OK = 0,
    DLSEC_INVALID_ARGUMENT,
    DLSEC_OUTPUT_TOO_SMALL,
    DLSEC_SELF_TEST_FAILED
} dlsec_status_t;

/* Encrypt exactly 55 AES-256-ECB blocks, with no padding, IV or Tag.
 * The caller supplies one effective key and serializes its atomic replacement
 * with this call. No key is retained and no heap or mutable global is used.
 *
 * Exact in-place operation is supported. Partial input/output overlap and
 * key/output overlap are rejected. On failure, the first min(capacity, 880)
 * bytes of a non-NULL output are zeroized, including overlapping input/key
 * bytes. Bytes after the 880-byte output field are never touched.
 * All non-NULL buffers must provide their declared readable/writable extent.
 * An internal public-key KAT runs before every encryption, including in-place.
 * This interface provides confidentiality only, without authentication/replay.
 */
dlsec_status_t dlsec_encrypt_data(const uint8_t *key, size_t key_length,
                                  const uint8_t *plaintext, size_t plaintext_length,
                                  uint8_t *ciphertext, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
