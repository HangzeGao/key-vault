/* TEST ONLY frame producer; authoritative expected bytes come from OpenSSL. */
#ifndef TEST_GCM_SEAL_H
#define TEST_GCM_SEAL_H
#include "sm4.h"
#include <string.h>
static void memzero(void *m, size_t n) { memset(m, 0, n); }
static void shift_right_one(uint8_t value[16]) {
    uint8_t carry = 0u;
    size_t index;
    for (index = 0u; index < 16u; ++index) {
        uint8_t next = (uint8_t)(value[index] & 1u);
        value[index] = (uint8_t)((value[index] >> 1) | (uint8_t)(carry << 7));
        carry = next;
    }
}

static void multiply(const uint8_t left[16], const uint8_t right[16], uint8_t output[16]) {
    uint8_t accumulator[16] = {0u};
    uint8_t value[16];
    size_t bit;
    memcpy(value, right, 16u);
    for (bit = 0u; bit < 128u; ++bit) {
        size_t index;
        if ((left[bit / 8u] & (uint8_t)(0x80u >> (bit % 8u))) != 0u) {
            for (index = 0u; index < 16u; ++index)
                accumulator[index] ^= value[index];
        }
        {
            uint8_t lsb = (uint8_t)(value[15] & 1u);
            shift_right_one(value);
            if (lsb != 0u)
                value[0] ^= 0xe1u;
        }
    }
    memcpy(output, accumulator, 16u);
    memzero(accumulator, sizeof(accumulator));
    memzero(value, sizeof(value));
}

static void ghash_block(uint8_t state[16], const uint8_t hash_key[16], const uint8_t block[16]) {
    uint8_t product[16];
    size_t index;
    for (index = 0u; index < 16u; ++index)
        state[index] ^= block[index];
    multiply(state, hash_key, product);
    memcpy(state, product, 16u);
    memzero(product, sizeof(product));
}

static void ghash_bytes(uint8_t state[16], const uint8_t hash_key[16], const uint8_t *data,
                        size_t length) {
    size_t offset = 0u;
    while (offset < length) {
        uint8_t block[16] = {0u};
        size_t count = length - offset;
        if (count > 16u)
            count = 16u;
        memcpy(block, &data[offset], count);
        ghash_block(state, hash_key, block);
        memzero(block, sizeof(block));
        offset += count;
    }
}

static void write_u64_be(uint8_t output[8], uint64_t value) {
    int index;
    for (index = 7; index >= 0; --index) {
        output[index] = (uint8_t)value;
        value >>= 8;
    }
}

static void increment_counter32(uint8_t counter[16]) {
    int index;
    for (index = 15; index >= 12; --index) {
        counter[index] = (uint8_t)(counter[index] + 1u);
        if (counter[index] != 0u)
            return;
    }
}

static int test_gcm_seal(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                         size_t aadlen, const uint8_t *plain, size_t n, uint8_t *cipher,
                         uint8_t tag[16]) {
    uint8_t h[16] = {0}, state[16] = {0}, j[16] = {0}, lengths[16] = {0}, mask[16];
    tcsec_sm4_key_t k;
    size_t off, i;
    if (tcsec_sm4_key_init(&k, key) != 0)
        return 0;
    tcsec_sm4_encrypt_with_key(&k, h, h);
    memcpy(j, nonce, 12);
    j[15] = 1;
    tcsec_sm4_encrypt_with_key(&k, j, mask);
    for (off = 0; off < n; off += 16) {
        uint8_t stream[16];
        size_t count = n - off;
        if (count > 16)
            count = 16;
        increment_counter32(j);
        tcsec_sm4_encrypt_with_key(&k, j, stream);
        for (i = 0; i < count; i++)
            cipher[off + i] = plain[off + i] ^ stream[i];
    }
    ghash_bytes(state, h, aad, aadlen);
    ghash_bytes(state, h, cipher, n);
    write_u64_be(lengths, aadlen * 8u);
    write_u64_be(lengths + 8, n * 8u);
    ghash_block(state, h, lengths);
    for (i = 0; i < 16; i++) {
        tag[i] = state[i] ^ mask[i];
    }
    tcsec_sm4_key_clear(&k);
    return 1;
}
#endif
