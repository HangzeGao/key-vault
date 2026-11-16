#include "tc_security_kdf.h"
#include "commissioning_confirmation.h"

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
    uint8_t input[4u + 32u + 1u + 15u + 4u];
    uint8_t tag[16];
    size_t produced = 0u;
    uint32_t counter = 1u;
    if (root == NULL || output == NULL || output_length != TCSEC_SM4_KEY_LENGTH ||
        root_length != TCSEC_SM4_KEY_LENGTH || output_capacity < output_length ||
        label_length > 32u || context_length > 15u)
        return -1;
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
    static const uint8_t label[] = "TC-GCM32-V1";
    uint8_t context[15];
    if (ordinary_suite != TCSEC_SUITE_SM4_GCM_32)
        return -1;
    write_u16(&context[0], spacecraft_id); context[2] = 1u;
    write_u16(&context[3], (uint16_t)ordinary_suite); write_u16(&context[5], spi);
    write_u32(&context[7], security_epoch); write_u32(&context[11], key_version);
    return derive(root, root_length, TCSEC_SM4_KEY_LENGTH, label, sizeof(label) - 1u, context,
                  sizeof(context), output, output_capacity);
}

int tcsec_derive_recovery_key(const uint8_t *root, size_t root_length,
                              uint16_t spacecraft_id, tcsec_suite_t recovery_suite,
                              uint16_t spi, uint32_t recovery_key_version,
                              uint8_t *output, size_t output_capacity) {
    static const uint8_t label[] = "TC-GCM128-RECOVERY-V1";
    uint8_t context[10];
    if (recovery_suite != TCSEC_SUITE_SM4_GCM) return -1;
    write_u16(&context[0], spacecraft_id); write_u16(&context[2], (uint16_t)recovery_suite);
    write_u16(&context[4], spi); write_u32(&context[6], recovery_key_version);
    return derive(root, root_length, TCSEC_SM4_KEY_LENGTH,
                  label, sizeof(label) - 1u,
                  context, sizeof(context), output, output_capacity);
}

static uint8_t confirmation_difference(const uint8_t *left, const uint8_t *right, size_t length) {
    uint8_t difference = 0u;
    size_t index;
    for (index = 0u; index < length; ++index) difference |= (uint8_t)(left[index] ^ right[index]);
    return difference;
}

static int confirmation_proof(const uint8_t *current, const uint8_t *recovery,
                              const uint8_t *transcript, uint8_t direction, uint8_t *proof) {
    static const uint8_t kdf_label[] = "TC-CONFIRM-KDF-V1";
    static const uint8_t mac_label[] = "TC-CONFIRM-MAC-V1";
    static const uint8_t zero[32] = {0u};
    uint8_t derivation[4u + sizeof(kdf_label) + 1u + TCSEC_CONFIRM_TRANSCRIPT_LENGTH + 4u];
    uint8_t message[sizeof(mac_label) + 2u + TCSEC_CONFIRM_TRANSCRIPT_LENGTH];
    uint8_t key[16];
    const uint8_t *roots[2] = {current, recovery};
    size_t index;
    if (proof == NULL) return -1;
    memset(proof, 0, TCSEC_CONFIRM_PROOF_LENGTH);
    if (current == NULL || recovery == NULL || transcript == NULL ||
        confirmation_difference(current, recovery, 16u) == 0u) return -1;
    for (index = 0u; index < TCSEC_CONFIRM_TRANSCRIPT_LENGTH; index += 32u) {
        if (memcmp(&transcript[index], zero, sizeof(zero)) == 0) return -1;
    }
    if (memcmp(&transcript[64], &transcript[96], 32u) == 0 ||
        memcmp(&transcript[128], &transcript[160], 32u) == 0) return -1;
    write_u32(derivation, 1u);
    memcpy(&derivation[4], kdf_label, sizeof(kdf_label));
    memcpy(&derivation[4u + sizeof(kdf_label) + 1u], transcript, TCSEC_CONFIRM_TRANSCRIPT_LENGTH);
    write_u32(&derivation[sizeof(derivation) - 4u], 128u);
    memcpy(message, mac_label, sizeof(mac_label));
    message[sizeof(mac_label)] = direction;
    memcpy(&message[sizeof(mac_label) + 2u], transcript, TCSEC_CONFIRM_TRANSCRIPT_LENGTH);
    for (index = 0u; index < 2u; ++index) {
        derivation[4u + sizeof(kdf_label)] = (uint8_t)(index + 1u);
        message[sizeof(mac_label) + 1u] = (uint8_t)(index + 1u);
        cmac(roots[index], derivation, sizeof(derivation), key);
        cmac(key, message, sizeof(message), &proof[index * 16u]);
        zeroize(key, sizeof(key));
    }
    return 0;
}

int tcsec_confirm_flight(const uint8_t current[16], const uint8_t recovery[16],
                         const uint8_t transcript[TCSEC_CONFIRM_TRANSCRIPT_LENGTH],
                         uint8_t proof[TCSEC_CONFIRM_PROOF_LENGTH]) {
    return confirmation_proof(current, recovery, transcript, 2u, proof);
}

int tcsec_confirm_verify_ground(const uint8_t current[16], const uint8_t recovery[16],
                                const uint8_t transcript[TCSEC_CONFIRM_TRANSCRIPT_LENGTH],
                                const uint8_t proof[TCSEC_CONFIRM_PROOF_LENGTH]) {
    uint8_t expected[TCSEC_CONFIRM_PROOF_LENGTH];
    int result;
    if (proof == NULL || confirmation_proof(current, recovery, transcript, 1u, expected) != 0) return -1;
    result = confirmation_difference(expected, proof, sizeof(expected)) == 0u ? 0 : -1;
    zeroize(expected, sizeof(expected));
    return result;
}
