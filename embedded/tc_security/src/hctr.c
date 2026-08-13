#include "hctr.h"

#include "sm4.h"

#include <limits.h>
#include <string.h>

#define BLOCK_LENGTH 16u

static void zeroize(void *memory, size_t length) {
    volatile uint8_t *cursor = (volatile uint8_t *)memory;
    while (length-- != 0u) *cursor++ = 0u;
}

static void xor_block(uint8_t output[BLOCK_LENGTH], const uint8_t left[BLOCK_LENGTH],
                      const uint8_t right[BLOCK_LENGTH]) {
    size_t index;
    for (index = 0u; index < BLOCK_LENGTH; ++index)
        output[index] = (uint8_t)(left[index] ^ right[index]);
}

static void shift_right_one(uint8_t value[BLOCK_LENGTH]) {
    uint8_t carry = 0u;
    size_t index;
    for (index = 0u; index < BLOCK_LENGTH; ++index) {
        uint8_t next = (uint8_t)(value[index] & 1u);
        value[index] = (uint8_t)((value[index] >> 1) | (uint8_t)(carry << 7));
        carry = next;
    }
}

/* GHASH field multiplication with x^128+x^7+x^2+x+1 and the bit ordering
 * used by GB/T 17964-2021 HCTR. */
static void multiply(const uint8_t left[BLOCK_LENGTH],
                     const uint8_t right[BLOCK_LENGTH],
                     uint8_t output[BLOCK_LENGTH]) {
    uint8_t accumulator[BLOCK_LENGTH] = {0u};
    uint8_t value[BLOCK_LENGTH];
    size_t bit;
    memcpy(value, right, sizeof(value));
    for (bit = 0u; bit < 128u; ++bit) {
        size_t index;
        if ((left[bit / 8u] & (uint8_t)(0x80u >> (bit % 8u))) != 0u)
            for (index = 0u; index < BLOCK_LENGTH; ++index)
                accumulator[index] ^= value[index];
        {
            uint8_t lsb = (uint8_t)(value[BLOCK_LENGTH - 1u] & 1u);
            shift_right_one(value);
            if (lsb != 0u) value[0] ^= 0xe1u;
        }
    }
    memcpy(output, accumulator, BLOCK_LENGTH);
    zeroize(accumulator, sizeof(accumulator));
    zeroize(value, sizeof(value));
}

static void hash_block(uint8_t state[BLOCK_LENGTH], const uint8_t hash_key[BLOCK_LENGTH],
                       const uint8_t block[BLOCK_LENGTH]) {
    uint8_t product[BLOCK_LENGTH];
    size_t index;
    for (index = 0u; index < BLOCK_LENGTH; ++index) state[index] ^= block[index];
    multiply(state, hash_key, product);
    memcpy(state, product, BLOCK_LENGTH);
    zeroize(product, sizeof(product));
}

static void write_u64_be(uint8_t output[8], uint64_t value) {
    int index;
    for (index = 7; index >= 0; --index) {
        output[index] = (uint8_t)value;
        value >>= 8;
    }
}

/* H_h(message || tweak), including the bit length of that concatenation. */
static int universal_hash(const uint8_t hash_key[BLOCK_LENGTH],
                          const uint8_t tweak[BLOCK_LENGTH],
                          const uint8_t *message, size_t message_length,
                          uint8_t output[BLOCK_LENGTH]) {
    uint8_t state[BLOCK_LENGTH] = {0u};
    uint8_t block[BLOCK_LENGTH] = {0u};
    size_t offset = 0u;
    size_t remaining;
#if SIZE_MAX > UINT32_MAX
    if (message_length > (UINT64_MAX / 8u) - BLOCK_LENGTH) return -1;
#endif
    while (message_length - offset >= BLOCK_LENGTH) {
        hash_block(state, hash_key, &message[offset]);
        offset += BLOCK_LENGTH;
    }
    remaining = message_length - offset;
    if (remaining == 0u) {
        hash_block(state, hash_key, tweak);
    } else {
        size_t index;
        memcpy(block, &message[offset], remaining);
        memcpy(&block[remaining], tweak, BLOCK_LENGTH - remaining);
        hash_block(state, hash_key, block);
        /* GB/T 17964 HCTR's second partial block is not ordinary
         * concatenation padding. Preserve the bytes not overwritten by this
         * copy, then clear the suffix exactly as specified. */
        memmove(block, &tweak[remaining], BLOCK_LENGTH - remaining);
        for (index = remaining; index < BLOCK_LENGTH; ++index) block[index] = 0u;
        hash_block(state, hash_key, block);
    }
    memset(block, 0, sizeof(block));
    write_u64_be(&block[8], ((uint64_t)message_length + BLOCK_LENGTH) * 8u);
    hash_block(state, hash_key, block);
    memcpy(output, state, BLOCK_LENGTH);
    zeroize(state, sizeof(state));
    zeroize(block, sizeof(block));
    return 0;
}

static void ctr_xor(const tcsec_sm4_key_t *key, const uint8_t base[BLOCK_LENGTH],
                    const uint8_t *input, uint8_t *output, size_t length) {
    uint8_t counter[BLOCK_LENGTH];
    uint8_t number[BLOCK_LENGTH] = {0u};
    uint8_t stream[BLOCK_LENGTH];
    uint64_t block_number = 1u;
    size_t offset = 0u;
    while (offset < length) {
        size_t count = length - offset;
        size_t index;
        if (count > BLOCK_LENGTH) count = BLOCK_LENGTH;
        memset(number, 0, sizeof(number));
        write_u64_be(&number[8], block_number++);
        xor_block(counter, base, number);
        tcsec_sm4_encrypt_with_key(key, counter, stream);
        for (index = 0u; index < count; ++index)
            output[offset + index] = (uint8_t)(input[offset + index] ^ stream[index]);
        offset += count;
    }
    zeroize(counter, sizeof(counter));
    zeroize(number, sizeof(number));
    zeroize(stream, sizeof(stream));
}

static int hctr_crypt(const uint8_t working_key[TCSEC_HCTR_WORKING_KEY_LENGTH],
                      const uint8_t tweak[TCSEC_HCTR_TWEAK_LENGTH],
                      const uint8_t *input, uint8_t *output, size_t length,
                      int decrypt) {
    tcsec_sm4_key_t key;
    uint8_t z1[BLOCK_LENGTH];
    uint8_t z2[BLOCK_LENGTH];
    int result = -1;
    if (working_key == NULL || tweak == NULL || input == NULL || output == NULL ||
        length < BLOCK_LENGTH) return -1;
    if (tcsec_sm4_key_init(&key, working_key) != 0) return -1;
    if (decrypt != 0) {
        if (universal_hash(&working_key[BLOCK_LENGTH], tweak, &input[BLOCK_LENGTH],
                           length - BLOCK_LENGTH, z2) != 0) goto done;
        xor_block(z2, z2, input);
        tcsec_sm4_decrypt_with_key(&key, z2, z1);
        xor_block(z2, z2, z1);
        ctr_xor(&key, z2, &input[BLOCK_LENGTH], &output[BLOCK_LENGTH],
                length - BLOCK_LENGTH);
        (void)universal_hash(&working_key[BLOCK_LENGTH], tweak, &output[BLOCK_LENGTH],
                             length - BLOCK_LENGTH, z2);
        xor_block(output, z2, z1);
    } else {
        if (universal_hash(&working_key[BLOCK_LENGTH], tweak, &input[BLOCK_LENGTH],
                           length - BLOCK_LENGTH, z1) != 0) goto done;
        xor_block(z1, z1, input);
        tcsec_sm4_encrypt_with_key(&key, z1, z2);
        xor_block(z1, z1, z2);
        ctr_xor(&key, z1, &input[BLOCK_LENGTH], &output[BLOCK_LENGTH],
                length - BLOCK_LENGTH);
        (void)universal_hash(&working_key[BLOCK_LENGTH], tweak, &output[BLOCK_LENGTH],
                             length - BLOCK_LENGTH, z1);
        xor_block(output, z2, z1);
    }
    result = 0;
done:
    tcsec_sm4_key_clear(&key);
    zeroize(z1, sizeof(z1));
    zeroize(z2, sizeof(z2));
    if (result != 0) zeroize(output, length);
    return result;
}

int tcsec_sm4_hctr_encrypt(const uint8_t working_key[TCSEC_HCTR_WORKING_KEY_LENGTH],
                           const uint8_t tweak[TCSEC_HCTR_TWEAK_LENGTH],
                           const uint8_t *plaintext, uint8_t *ciphertext,
                           size_t length) {
    return hctr_crypt(working_key, tweak, plaintext, ciphertext, length, 0);
}

int tcsec_sm4_hctr_decrypt(const uint8_t working_key[TCSEC_HCTR_WORKING_KEY_LENGTH],
                           const uint8_t tweak[TCSEC_HCTR_TWEAK_LENGTH],
                           const uint8_t *ciphertext, uint8_t *plaintext,
                           size_t length) {
    return hctr_crypt(working_key, tweak, ciphertext, plaintext, length, 1);
}
