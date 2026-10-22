#include "downlink_security.h"

#include <string.h>

/* FIPS 197 AES-256, column-major state. SubBytes computes inversion in GF(2^8)
 * rather than indexing a secret-dependent table. Loop/round counts and key
 * expansion branches depend only on public indices. Target timing/power
 * evaluation is still required; this source is not a side-channel certificate.
 */
static void clear_bytes(void *buffer, size_t length) {
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;
    while (length != 0u) { *bytes++ = 0u; --length; }
}

static uint8_t xtime(uint8_t value) {
    return (uint8_t)((value << 1) ^ (0x1bu & (0u - (value >> 7))));
}

static uint8_t multiply(uint8_t left, uint8_t right) {
    uint8_t result = 0u;
    unsigned bit;
    for (bit = 0u; bit < 8u; ++bit) {
        result ^= (uint8_t)(left & (0u - (right & 1u)));
        left = xtime(left);
        right >>= 1;
    }
    return result;
}

static uint8_t rotate(uint8_t value, unsigned bits) {
    return (uint8_t)((value << bits) | (value >> (8u - bits)));
}

static uint8_t substitute(uint8_t value) {
    /* x^254, including 0 -> 0. Fixed addition chain for multiplicative inverse. */
    uint8_t x2 = multiply(value, value);
    uint8_t x3 = multiply(x2, value);
    uint8_t x6 = multiply(x3, x3);
    uint8_t x12 = multiply(x6, x6);
    uint8_t x15 = multiply(x12, x3);
    uint8_t x30 = multiply(x15, x15);
    uint8_t x60 = multiply(x30, x30);
    uint8_t x120 = multiply(x60, x60);
    uint8_t x240 = multiply(x120, x120);
    uint8_t inverse = multiply(multiply(x240, x12), x2);
    return (uint8_t)(inverse ^ rotate(inverse, 1u) ^ rotate(inverse, 2u) ^
                     rotate(inverse, 3u) ^ rotate(inverse, 4u) ^ 0x63u);
}

static void expand_key(const uint8_t key[32], uint8_t expanded[240]) {
    size_t offset;
    uint8_t rcon = 1u;
    uint8_t word[4];
    memcpy(expanded, key, 32u);
    for (offset = 32u; offset < 240u; offset += 4u) {
        size_t index;
        memcpy(word, expanded + offset - 4u, 4u);
        if (offset % 32u == 0u) {
            uint8_t first = word[0];
            word[0] = (uint8_t)(substitute(word[1]) ^ rcon);
            word[1] = substitute(word[2]);
            word[2] = substitute(word[3]);
            word[3] = substitute(first);
            rcon = xtime(rcon);
        } else if (offset % 32u == 16u) {
            for (index = 0u; index < 4u; ++index) word[index] = substitute(word[index]);
        }
        for (index = 0u; index < 4u; ++index)
            expanded[offset + index] = (uint8_t)(expanded[offset + index - 32u] ^ word[index]);
    }
    clear_bytes(word, sizeof(word));
}

static void encrypt_block(const uint8_t expanded[240], const uint8_t input[16], uint8_t output[16]) {
    uint8_t state[16];
    uint8_t shifted[16];
    unsigned round;
    size_t index;
    for (index = 0u; index < 16u; ++index) state[index] = (uint8_t)(input[index] ^ expanded[index]);
    for (round = 1u; round <= 14u; ++round) {
        size_t column;
        for (index = 0u; index < 16u; ++index) {
            size_t row = index % 4u;
            shifted[index] = substitute(state[row + 4u * ((index / 4u + row) % 4u)]);
        }
        memcpy(state, shifted, sizeof(state));
        if (round != 14u) {
            for (column = 0u; column < 16u; column += 4u) {
                uint8_t a = state[column], b = state[column + 1u];
                uint8_t c = state[column + 2u], d = state[column + 3u];
                uint8_t sum = (uint8_t)(a ^ b ^ c ^ d);
                state[column] ^= (uint8_t)(sum ^ xtime((uint8_t)(a ^ b)));
                state[column + 1u] ^= (uint8_t)(sum ^ xtime((uint8_t)(b ^ c)));
                state[column + 2u] ^= (uint8_t)(sum ^ xtime((uint8_t)(c ^ d)));
                state[column + 3u] ^= (uint8_t)(sum ^ xtime((uint8_t)(d ^ a)));
            }
        }
        for (index = 0u; index < 16u; ++index) state[index] ^= expanded[16u * round + index];
    }
    memcpy(output, state, 16u);
    clear_bytes(state, sizeof(state));
    clear_bytes(shifted, sizeof(shifted));
}

static int self_test(void) {
    /* NIST SP 800-38A F.1.5, first block. Public TEST ONLY material. */
    static const uint8_t key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const uint8_t plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t expected[16] = {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
    };
    uint8_t expanded[240], output[16], difference = 0u;
    size_t index;
    expand_key(key, expanded);
    encrypt_block(expanded, plaintext, output);
#if defined(DLSEC_TEST_SELF_TEST_FAILURE)
    output[0] ^= 1u;
#endif
    for (index = 0u; index < sizeof(output); ++index) difference |= (uint8_t)(output[index] ^ expected[index]);
    clear_bytes(expanded, sizeof(expanded));
    clear_bytes(output, sizeof(output));
    return difference == 0u;
}

static int overlaps(const uint8_t *left, size_t left_length, const uint8_t *right, size_t right_length) {
    uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return a <= b ? b - a < left_length : a - b < right_length;
}

static dlsec_status_t reject(uint8_t *output, size_t capacity, dlsec_status_t status) {
    if (output != NULL) clear_bytes(output, capacity < DLSEC_DATA_LENGTH ? capacity : DLSEC_DATA_LENGTH);
    return status;
}

dlsec_status_t dlsec_encrypt_data(const uint8_t *key, size_t key_length,
                                  const uint8_t *plaintext, size_t plaintext_length,
                                  uint8_t *ciphertext, size_t capacity) {
    uint8_t expanded[240];
    size_t offset;
    if (key == NULL || key_length != DLSEC_KEY_LENGTH || plaintext == NULL ||
        plaintext_length != DLSEC_DATA_LENGTH || ciphertext == NULL)
        return reject(ciphertext, capacity, DLSEC_INVALID_ARGUMENT);
    if (capacity < DLSEC_DATA_LENGTH) return reject(ciphertext, capacity, DLSEC_OUTPUT_TOO_SMALL);
    if ((plaintext != ciphertext && overlaps(plaintext, DLSEC_DATA_LENGTH, ciphertext, DLSEC_DATA_LENGTH)) ||
        overlaps(key, DLSEC_KEY_LENGTH, ciphertext, DLSEC_DATA_LENGTH))
        return reject(ciphertext, capacity, DLSEC_INVALID_ARGUMENT);
    if (!self_test()) return reject(ciphertext, capacity, DLSEC_SELF_TEST_FAILED);
    expand_key(key, expanded);
    for (offset = 0u; offset < DLSEC_DATA_LENGTH; offset += 16u)
        encrypt_block(expanded, plaintext + offset, ciphertext + offset);
    clear_bytes(expanded, sizeof(expanded));
    return DLSEC_OK;
}
