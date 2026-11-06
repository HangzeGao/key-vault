#ifndef TCSEC_GCM_H
#define TCSEC_GCM_H

#include "parameters.h"

#include <stddef.h>
#include <stdint.h>

int tcsec_gcm_open(tcsec_suite_t suite,
                   const uint8_t *key,
                   const uint8_t nonce[TCSEC_GCM_NONCE_LENGTH],
                   const uint8_t *aad,
                   size_t aad_length,
                   const uint8_t *ciphertext,
                   size_t ciphertext_length,
                   const uint8_t tag[TCSEC_GCM_TAG_LENGTH],
                   uint8_t *plaintext);

int tcsec_gcm_open_short(const uint8_t key[16], const uint8_t nonce[12], const uint8_t *aad,
                         size_t aad_length, const uint8_t *ciphertext, size_t length,
                         const uint8_t tag[4], uint8_t *plaintext);
#endif
