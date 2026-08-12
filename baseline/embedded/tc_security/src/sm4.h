#ifndef TCSEC_SM4_H
#define TCSEC_SM4_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t round_keys[32];
    uint8_t backend;
    uint8_t backend_inverse;
} tcsec_sm4_key_t;

int tcsec_sm4_key_init(tcsec_sm4_key_t *context, const uint8_t key[16]);
void tcsec_sm4_key_clear(tcsec_sm4_key_t *context);
void tcsec_sm4_encrypt_with_key(const tcsec_sm4_key_t *context,
                                const uint8_t input[16], uint8_t output[16]);
void tcsec_sm4_decrypt_with_key(const tcsec_sm4_key_t *context,
                                const uint8_t input[16], uint8_t output[16]);

int tcsec_sm4_encrypt_block(const uint8_t key[16],
                            const uint8_t input[16],
                            uint8_t output[16]);

/* Diagnostic only; selection remains private to the SM4 module. */
const char *tcsec_sm4_backend_name(const tcsec_sm4_key_t *context);

#endif
