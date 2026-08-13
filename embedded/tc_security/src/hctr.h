#ifndef TCSEC_HCTR_H
#define TCSEC_HCTR_H

#include <stddef.h>
#include <stdint.h>

#define TCSEC_HCTR_WORKING_KEY_LENGTH 32u
#define TCSEC_HCTR_TWEAK_LENGTH 16u

int tcsec_sm4_hctr_encrypt(const uint8_t working_key[TCSEC_HCTR_WORKING_KEY_LENGTH],
                           const uint8_t tweak[TCSEC_HCTR_TWEAK_LENGTH],
                           const uint8_t *plaintext, uint8_t *ciphertext,
                           size_t length);

int tcsec_sm4_hctr_decrypt(const uint8_t working_key[TCSEC_HCTR_WORKING_KEY_LENGTH],
                           const uint8_t tweak[TCSEC_HCTR_TWEAK_LENGTH],
                           const uint8_t *ciphertext, uint8_t *plaintext,
                           size_t length);

#endif
