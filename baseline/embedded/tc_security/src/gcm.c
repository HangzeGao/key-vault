#include "gcm.h"

#include "sm4.h"

#include <string.h>

static void zeroize(void *memory, size_t length) {
    volatile uint8_t *cursor = (volatile uint8_t *)memory;
    while (length-- != 0u) *cursor++ = 0u;
}

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
            for (index = 0u; index < 16u; ++index) accumulator[index] ^= value[index];
        }
        {
            uint8_t lsb = (uint8_t)(value[15] & 1u);
            shift_right_one(value);
            if (lsb != 0u) value[0] ^= 0xe1u;
        }
    }
    memcpy(output, accumulator, 16u);
    zeroize(accumulator, sizeof(accumulator));
    zeroize(value, sizeof(value));
}

static void ghash_block(uint8_t state[16], const uint8_t hash_key[16], const uint8_t block[16]) {
    uint8_t product[16];
    size_t index;
    for (index = 0u; index < 16u; ++index) state[index] ^= block[index];
    multiply(state, hash_key, product);
    memcpy(state, product, 16u);
    zeroize(product, sizeof(product));
}

static void ghash_bytes(uint8_t state[16], const uint8_t hash_key[16],
                        const uint8_t *data, size_t length) {
    size_t offset = 0u;
    while (offset < length) {
        uint8_t block[16] = {0u};
        size_t count = length - offset;
        if (count > 16u) count = 16u;
        memcpy(block, &data[offset], count);
        ghash_block(state, hash_key, block);
        zeroize(block, sizeof(block));
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
        if (counter[index] != 0u) return;
    }
}

static int constant_time_equal(const uint8_t left[16], const uint8_t right[16]) {
    uint8_t difference = 0u;
    size_t index;
    for (index = 0u; index < 16u; ++index) difference |= (uint8_t)(left[index] ^ right[index]);
    return difference == 0u;
}

int tcsec_gcm_open(tcsec_suite_t suite, const uint8_t *key,
                   const uint8_t nonce[TCSEC_GCM_NONCE_LENGTH],
                   const uint8_t *aad, size_t aad_length,
                   const uint8_t *ciphertext, size_t ciphertext_length,
                   const uint8_t tag[TCSEC_GCM_TAG_LENGTH], uint8_t *plaintext) {
    uint8_t hash_key[16] = {0u};
    uint8_t state[16] = {0u};
    uint8_t length_block[16] = {0u};
    uint8_t j0[16] = {0u};
    uint8_t mask[16];
    uint8_t expected_tag[16];
    tcsec_sm4_key_t key_context;
    size_t offset = 0u;
    int result = -1;
    if (key == NULL || nonce == NULL || tag == NULL ||
        (aad_length != 0u && aad == NULL) ||
        (ciphertext_length != 0u && (ciphertext == NULL || plaintext == NULL))) return -1;
#if SIZE_MAX > UINT32_MAX
    if (aad_length > UINT64_MAX / 8u || ciphertext_length > UINT64_MAX / 8u ||
        ciphertext_length > ((uint64_t)UINT32_MAX - 1u) * 16u) return -1;
#endif
    if (suite != TCSEC_SUITE_SM4_GCM || tcsec_sm4_key_init(&key_context, key) != 0) return -1;
    tcsec_sm4_encrypt_with_key(&key_context, hash_key, hash_key);
    ghash_bytes(state, hash_key, aad, aad_length);
    ghash_bytes(state, hash_key, ciphertext, ciphertext_length);
    write_u64_be(&length_block[0], (uint64_t)aad_length * 8u);
    write_u64_be(&length_block[8], (uint64_t)ciphertext_length * 8u);
    ghash_block(state, hash_key, length_block);
    memcpy(j0, nonce, TCSEC_GCM_NONCE_LENGTH);
    j0[15] = 1u;
    tcsec_sm4_encrypt_with_key(&key_context, j0, mask);
    for (offset = 0u; offset < 16u; ++offset) expected_tag[offset] = (uint8_t)(state[offset] ^ mask[offset]);
    if (!constant_time_equal(expected_tag, tag)) {
        result = -2;
        goto done;
    }
    memcpy(mask, j0, sizeof(mask));
    offset = 0u;
    while (offset < ciphertext_length) {
        uint8_t stream[16];
        size_t count = ciphertext_length - offset;
        size_t index;
        if (count > 16u) count = 16u;
        increment_counter32(mask);
        tcsec_sm4_encrypt_with_key(&key_context, mask, stream);
        for (index = 0u; index < count; ++index) plaintext[offset + index] = (uint8_t)(ciphertext[offset + index] ^ stream[index]);
        zeroize(stream, sizeof(stream));
        offset += count;
    }
    result = 0;
done:
    tcsec_sm4_key_clear(&key_context);
    zeroize(hash_key, sizeof(hash_key));
    zeroize(state, sizeof(state));
    zeroize(length_block, sizeof(length_block));
    zeroize(j0, sizeof(j0));
    zeroize(mask, sizeof(mask));
    zeroize(expected_tag, sizeof(expected_tag));
    if (result != 0 && plaintext != NULL) zeroize(plaintext, ciphertext_length);
    return result;
}
