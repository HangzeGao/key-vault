#include "tc_security_kdf.h"

#include "sm4.h"

#include <string.h>

static void zeroize(void *memory, size_t length) {
    volatile uint8_t *cursor = (volatile uint8_t *)memory;
    while (length-- != 0u) *cursor++ = 0u;
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

static void cmac(const uint8_t *key, const uint8_t *message,
                 size_t length, uint8_t tag[16]) {
    uint8_t zero[16] = {0u};
    uint8_t l[16];
    uint8_t k1[16];
    uint8_t k2[16];
    uint8_t state[16] = {0u};
    uint8_t block[16];
    size_t blocks = length == 0u ? 1u : (length + 15u) / 16u;
    size_t index;
    (void)tcsec_sm4_encrypt_block(key, zero, l);
    double_block(l, k1);
    double_block(k1, k2);
    for (index = 0u; index + 1u < blocks; ++index) {
        size_t byte;
        for (byte = 0u; byte < 16u; ++byte) block[byte] = (uint8_t)(state[byte] ^ message[index * 16u + byte]);
        (void)tcsec_sm4_encrypt_block(key, block, state);
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
    (void)tcsec_sm4_encrypt_block(key, block, tag);
    zeroize(l, sizeof(l)); zeroize(k1, sizeof(k1)); zeroize(k2, sizeof(k2));
    zeroize(state, sizeof(state)); zeroize(block, sizeof(block));
}

#if defined(TCSEC_TEST_CRYPTO_PRIMITIVES)
int tcsec_test_sm4_cmac(const uint8_t key[16], const uint8_t *message,
                        size_t length, uint8_t tag[16]) {
    if (key == NULL || tag == NULL || (message == NULL && length != 0u)) return -1;
    cmac(key, message, length, tag);
    return 0;
}
#endif

static void write_u16(uint8_t output[2], uint16_t value) {
    output[0] = (uint8_t)(value >> 8); output[1] = (uint8_t)value;
}

static void write_u32(uint8_t output[4], uint32_t value) {
    output[0] = (uint8_t)(value >> 24); output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8); output[3] = (uint8_t)value;
}

static int derive(const uint8_t *root, size_t root_length, size_t output_length,
                  const uint8_t *label, size_t label_length,
                  const uint8_t *context, size_t context_length,
                  uint8_t *output, size_t output_capacity) {
    uint8_t input[4u + 15u + 1u + 15u + 4u];
    uint8_t tag[16];
    size_t produced = 0u;
    uint32_t counter = 1u;
    if (root == NULL || output == NULL ||
        (output_length != TCSEC_SM4_KEY_LENGTH &&
         output_length != TCSEC_HCTR_WORKING_KEY_LENGTH) ||
        root_length != TCSEC_SM4_KEY_LENGTH ||
        output_capacity < output_length || label_length > 15u || context_length > 15u) return -1;
    while (produced < output_length) {
        size_t input_length = 0u;
        size_t count;
        write_u32(&input[input_length], counter++); input_length += 4u;
        memcpy(&input[input_length], label, label_length); input_length += label_length;
        input[input_length++] = 0u;
        memcpy(&input[input_length], context, context_length); input_length += context_length;
        write_u32(&input[input_length], (uint32_t)(output_length * 8u)); input_length += 4u;
        cmac(root, input, input_length, tag);
        count = output_length - produced;
        if (count > sizeof(tag)) count = sizeof(tag);
        memcpy(&output[produced], tag, count);
        produced += count;
    }
    zeroize(input, sizeof(input)); zeroize(tag, sizeof(tag));
    return 0;
}

int tcsec_derive_ordinary_key(const uint8_t *root, size_t root_length,
                              uint16_t spacecraft_id, tcsec_suite_t ordinary_suite,
                              uint16_t spi, uint32_t security_epoch, uint32_t key_version,
                              uint8_t *output, size_t output_capacity) {
    static const uint8_t label[] = "TC-TRAFFIC";
    uint8_t context[15];
    if (ordinary_suite != TCSEC_SUITE_SM4_HCTR) return -1;
    write_u16(&context[0], spacecraft_id); context[2] = 1u;
    write_u16(&context[3], (uint16_t)ordinary_suite); write_u16(&context[5], spi);
    write_u32(&context[7], security_epoch); write_u32(&context[11], key_version);
    return derive(root, root_length, TCSEC_HCTR_WORKING_KEY_LENGTH,
                  label, sizeof(label) - 1u,
                  context, sizeof(context), output, output_capacity);
}

int tcsec_derive_recovery_key(const uint8_t *root, size_t root_length,
                              uint16_t spacecraft_id, tcsec_suite_t recovery_suite,
                              uint16_t spi, uint32_t recovery_key_version,
                              uint8_t *output, size_t output_capacity) {
    static const uint8_t label[] = "TC-RECOVERY-GCM";
    uint8_t context[10];
    if (recovery_suite != TCSEC_SUITE_SM4_GCM) return -1;
    write_u16(&context[0], spacecraft_id); write_u16(&context[2], (uint16_t)recovery_suite);
    write_u16(&context[4], spi); write_u32(&context[6], recovery_key_version);
    return derive(root, root_length, TCSEC_SM4_KEY_LENGTH,
                  label, sizeof(label) - 1u,
                  context, sizeof(context), output, output_capacity);
}
