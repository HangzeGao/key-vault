#ifndef TCSEC_AES256_H
#define TCSEC_AES256_H

#include <stddef.h>
#include <stdint.h>

int tcsec_aes256_ctr_xor(const uint8_t key[32],
                         const uint8_t initial_counter[16],
                         const uint8_t *input,
                         uint8_t *output,
                         size_t length);

int tcsec_aes256_encrypt_block(const uint8_t key[32],
                               const uint8_t input[16],
                               uint8_t output[16]);

#endif
