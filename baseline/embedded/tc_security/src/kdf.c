#include "tc_security_kdf.h"

#include "aes256.h"
#include "sm4.h"

#include <string.h>

static void zeroize(void *memory, size_t length) {
    volatile uint8_t *cursor = (volatile uint8_t *)memory;
    while (length-- != 0u) *cursor++ = 0u;
}

static size_t suite_key_length(tcsec_suite_t suite) {
    if (suite == TCSEC_SUITE_AES_256_CTR || suite == TCSEC_SUITE_AES_256_GCM) return 32u;
    if (suite == TCSEC_SUITE_SM4_CTR || suite == TCSEC_SUITE_SM4_GCM) return 16u;
    return 0u;
}

static int encrypt_block(tcsec_suite_t suite, const uint8_t *key,
                         const uint8_t input[16], uint8_t output[16]) {
    if (suite == TCSEC_SUITE_AES_256_CTR || suite == TCSEC_SUITE_AES_256_GCM)
        return tcsec_aes256_encrypt_block(key, input, output);
    if (suite == TCSEC_SUITE_SM4_CTR || suite == TCSEC_SUITE_SM4_GCM)
        return tcsec_sm4_encrypt_block(key, input, output);
    return -1;
}

static void double_block(const uint8_t input[16], uint8_t output[16]) {
    uint8_t carry = 0u;
    int index;
    for (index = 15; index >= 0; --index) {
        uint8_t next = (uint8_t)(input[index] >> 7);
        output[index] = (uint8_t)((input[index] << 1) | carry);
        carry = next;
    }
    if (carry != 0u) output[15] ^= 0x87u;
}

static int cmac(tcsec_suite_t suite, const uint8_t *key,
                const uint8_t *message, size_t length, uint8_t tag[16]) {
    uint8_t zero[16] = {0u};
    uint8_t l[16];
    uint8_t k1[16];
    uint8_t k2[16];
    uint8_t state[16] = {0u};
    uint8_t block[16];
    size_t blocks = length == 0u ? 1u : (length + 15u) / 16u;
    size_t index;
    if (encrypt_block(suite, key, zero, l) != 0) return -1;
    double_block(l, k1);
    double_block(k1, k2);
    for (index = 0u; index + 1u < blocks; ++index) {
        size_t byte;
        for (byte = 0u; byte < 16u; ++byte) block[byte] = (uint8_t)(state[byte] ^ message[index * 16u + byte]);
        if (encrypt_block(suite, key, block, state) != 0) goto fail;
    }
    {
        size_t offset = (blocks - 1u) * 16u;
        size_t remaining = length - offset;
        const uint8_t *subkey = k2;
        memset(block, 0, sizeof(block));
        if (remaining == 16u) {
            memcpy(block, &message[offset], 16u);
            subkey = k1;
        } else {
            if (remaining != 0u) memcpy(block, &message[offset], remaining);
            block[remaining] = 0x80u;
        }
        for (index = 0u; index < 16u; ++index) block[index] ^= (uint8_t)(state[index] ^ subkey[index]);
    }
    if (encrypt_block(suite, key, block, tag) != 0) goto fail;
    zeroize(l, sizeof(l)); zeroize(k1, sizeof(k1)); zeroize(k2, sizeof(k2));
    zeroize(state, sizeof(state)); zeroize(block, sizeof(block));
    return 0;
fail:
    zeroize(l, sizeof(l)); zeroize(k1, sizeof(k1)); zeroize(k2, sizeof(k2));
    zeroize(state, sizeof(state)); zeroize(block, sizeof(block));
    return -1;
}

static void write_u16(uint8_t output[2], uint16_t value) {
    output[0] = (uint8_t)(value >> 8); output[1] = (uint8_t)value;
}

static void write_u32(uint8_t output[4], uint32_t value) {
    output[0] = (uint8_t)(value >> 24); output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8); output[3] = (uint8_t)value;
}

static int derive(const uint8_t *root, size_t root_length, tcsec_suite_t suite,
                  const uint8_t *label, size_t label_length,
                  const uint8_t *context, size_t context_length,
                  uint8_t *output, size_t output_capacity) {
    uint8_t input[4u + 15u + 1u + 15u + 4u];
    uint8_t tag[16];
    size_t output_length = suite_key_length(suite);
    size_t produced = 0u;
    uint32_t counter = 1u;
    if (root == NULL || output == NULL || output_length == 0u || root_length != output_length ||
        output_capacity < output_length || label_length > 15u || context_length > 15u) return -1;
    while (produced < output_length) {
        size_t input_length = 0u;
        size_t count;
        write_u32(&input[input_length], counter++); input_length += 4u;
        memcpy(&input[input_length], label, label_length); input_length += label_length;
        input[input_length++] = 0u;
        memcpy(&input[input_length], context, context_length); input_length += context_length;
        write_u32(&input[input_length], (uint32_t)(output_length * 8u)); input_length += 4u;
        if (cmac(suite, root, input, input_length, tag) != 0) goto fail;
        count = output_length - produced;
        if (count > sizeof(tag)) count = sizeof(tag);
        memcpy(&output[produced], tag, count);
        produced += count;
    }
    zeroize(input, sizeof(input)); zeroize(tag, sizeof(tag));
    return 0;
fail:
    zeroize(input, sizeof(input)); zeroize(tag, sizeof(tag)); zeroize(output, output_length);
    return -1;
}

int tcsec_derive_ordinary_key(const uint8_t *root, size_t root_length,
                              uint16_t spacecraft_id, tcsec_suite_t ordinary_suite,
                              uint16_t spi, uint32_t security_epoch, uint32_t key_version,
                              uint8_t *output, size_t output_capacity) {
    static const uint8_t label[] = "TC-TRAFFIC";
    uint8_t context[15];
    if (ordinary_suite != TCSEC_SUITE_AES_256_CTR && ordinary_suite != TCSEC_SUITE_SM4_CTR) return -1;
    write_u16(&context[0], spacecraft_id); context[2] = 1u;
    write_u16(&context[3], (uint16_t)ordinary_suite); write_u16(&context[5], spi);
    write_u32(&context[7], security_epoch); write_u32(&context[11], key_version);
    return derive(root, root_length, ordinary_suite, label, sizeof(label) - 1u,
                  context, sizeof(context), output, output_capacity);
}

int tcsec_derive_recovery_key(const uint8_t *root, size_t root_length,
                              uint16_t spacecraft_id, tcsec_suite_t recovery_suite,
                              uint16_t spi, uint32_t recovery_key_version,
                              uint8_t *output, size_t output_capacity) {
    static const uint8_t label[] = "TC-RECOVERY-GCM";
    uint8_t context[10];
    if (recovery_suite != TCSEC_SUITE_AES_256_GCM && recovery_suite != TCSEC_SUITE_SM4_GCM) return -1;
    write_u16(&context[0], spacecraft_id); write_u16(&context[2], (uint16_t)recovery_suite);
    write_u16(&context[4], spi); write_u32(&context[6], recovery_key_version);
    return derive(root, root_length, recovery_suite, label, sizeof(label) - 1u,
                  context, sizeof(context), output, output_capacity);
}
