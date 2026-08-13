#include "sm4.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int neon_available;
static unsigned asm_encrypt_calls;
static unsigned asm_decrypt_calls;

int tcsec_test_armv7_neon_available(void) {
    return neon_available;
}

void tcsec_sm4_armv7_neon_encrypt(const uint8_t input[16], uint8_t output[16],
                                  const uint32_t round_keys[32]) {
    (void)input;
    (void)round_keys;
    ++asm_encrypt_calls;
    memset(output, 0xa5, 16u);
}

void tcsec_sm4_armv7_neon_decrypt(const uint8_t input[16], uint8_t output[16],
                                  const uint32_t round_keys[32]) {
    (void)input;
    (void)round_keys;
    ++asm_decrypt_calls;
    memset(output, 0x5a, 16u);
}

int main(void) {
    static const uint8_t key[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    static const uint8_t expected[16] = {
        0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46
    };
    uint8_t output[16];
    tcsec_sm4_key_t context;

    neon_available = 0;
    if (tcsec_sm4_key_init(&context, key) != 0 ||
        strcmp(tcsec_sm4_backend_name(&context), "software") != 0) return 1;
    tcsec_sm4_encrypt_with_key(&context, key, output);
    tcsec_sm4_key_clear(&context);
    if (memcmp(output, expected, sizeof(output)) != 0 || asm_encrypt_calls != 0u) return 1;

    neon_available = 1;
    if (tcsec_sm4_key_init(&context, key) != 0 ||
        strcmp(tcsec_sm4_backend_name(&context), "armv7-neon") != 0) return 1;
    tcsec_sm4_encrypt_with_key(&context, key, output);
    if (output[0] != 0xa5u || asm_encrypt_calls != 1u) return 1;
    tcsec_sm4_decrypt_with_key(&context, output, output);
    tcsec_sm4_key_clear(&context);
    if (output[0] != 0x5au || asm_decrypt_calls != 1u) return 1;

    puts("SM4 runtime backend dispatch test passed");
    return 0;
}
