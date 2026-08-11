#include "tc_security_nvm.h"

#include "tc_security_internal.h"

#include <string.h>

#define NVM_HEADER_LENGTH 44u
#define NVM_PAYLOAD_LENGTH 123u
#define NVM_TRAILER_LENGTH 8u
#define NVM_VERSION 1u

static const uint8_t nvm_magic[4] = {'T', 'C', 'S', '1'};

static void zeroize(void *memory, size_t length) {
    volatile uint8_t *cursor = (volatile uint8_t *)memory;
    if (memory == NULL) return;
    while (length-- != 0u) *cursor++ = 0u;
}

static uint16_t read_u16(const uint8_t *value) {
    return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static uint32_t read_u32(const uint8_t *value) {
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | value[3];
}

static uint64_t read_u64(const uint8_t *value) {
    uint64_t result = 0u;
    size_t index;
    for (index = 0u; index < 8u; ++index) result = (result << 8) | value[index];
    return result;
}

static void write_u16(uint8_t *output, uint16_t value) {
    output[0] = (uint8_t)(value >> 8); output[1] = (uint8_t)value;
}

static void write_u32(uint8_t *output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24); output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8); output[3] = (uint8_t)value;
}

static void write_u64(uint8_t *output, uint64_t value) {
    size_t index;
    for (index = 0u; index < 8u; ++index) {
        output[7u - index] = (uint8_t)value;
        value >>= 8;
    }
}

static uint32_t crc32c(const uint8_t *data, size_t length) {
    uint32_t crc = UINT32_MAX;
    size_t index;
    for (index = 0u; index < length; ++index) {
        uint8_t bit;
        crc ^= data[index];
        for (bit = 0u; bit < 8u; ++bit)
            crc = (crc & 1u) != 0u ? (crc >> 1) ^ UINT32_C(0x82f63b78) : crc >> 1;
    }
    return ~crc;
}

static int bytes_all_zero(const uint8_t *value, size_t length) {
    size_t index;
    uint8_t combined = 0u;
    for (index = 0u; index < length; ++index) combined |= value[index];
    return combined == 0u;
}

static void encode_replay(uint8_t **cursor, const tcsec_replay_state_t *state) {
    write_u32(*cursor, state->highest_iv); *cursor += 4u;
    write_u64(*cursor, state->bitmap); *cursor += 8u;
    *(*cursor)++ = state->seen;
}

static void decode_replay(const uint8_t **cursor, tcsec_replay_state_t *state) {
    state->highest_iv = read_u32(*cursor); *cursor += 4u;
    state->bitmap = read_u64(*cursor); *cursor += 8u;
    state->seen = *(*cursor)++;
}

tcsec_status_t tcsec_nvm_encode(const tcsec_nvm_image_t *image,
                                uint8_t *output,
                                size_t output_capacity,
                                size_t *output_length) {
    uint8_t *cursor;
    uint32_t checksum;
    const tcsec_ordinary_config_t *ordinary;
    const tcsec_recovery_config_t *recovery;
    if (image == NULL || output == NULL || output_length == NULL)
        return TCSEC_INVALID_ARGUMENT;
    *output_length = 0u;
    if (output_capacity < TCSEC_NVM_IMAGE_LENGTH) return TCSEC_OUTPUT_TOO_SMALL;
    if (image->generation == 0u ||
        bytes_all_zero(image->profile_digest, sizeof(image->profile_digest)) ||
        !tcsec_config_valid_internal(&image->config))
        return TCSEC_INVALID_CONFIGURATION;
    ordinary = &image->config.ordinary;
    recovery = &image->config.recovery;
    memset(output, 0, TCSEC_NVM_IMAGE_LENGTH);
    memcpy(output, nvm_magic, sizeof(nvm_magic));
    write_u16(&output[4], NVM_VERSION);
    write_u16(&output[6], NVM_PAYLOAD_LENGTH);
    write_u32(&output[8], image->generation);
    memcpy(&output[12], image->profile_digest, TCSEC_NVM_PROFILE_DIGEST_LENGTH);
    cursor = &output[NVM_HEADER_LENGTH];
    write_u16(cursor, ordinary->spacecraft_id); cursor += 2u;
    write_u16(cursor, (uint16_t)ordinary->suite); cursor += 2u;
    memcpy(cursor, ordinary->operational_root, TCSEC_ROOT_KEY_LENGTH); cursor += TCSEC_ROOT_KEY_LENGTH;
    write_u32(cursor, ordinary->root_version); cursor += 4u;
    write_u32(cursor, ordinary->current_epoch); cursor += 4u;
    write_u16(cursor, ordinary->current_spi); cursor += 2u;
    memcpy(cursor, ordinary->nonce_prefix, TCSEC_NONCE_PREFIX_LENGTH); cursor += TCSEC_NONCE_PREFIX_LENGTH;
    encode_replay(&cursor, &ordinary->replay);
    *cursor++ = ordinary->pending_root_present;
    write_u16(cursor, (uint16_t)ordinary->pending_suite); cursor += 2u;
    if (ordinary->pending_root_present != 0u)
        memcpy(cursor, ordinary->pending_operational_root, TCSEC_ROOT_KEY_LENGTH);
    cursor += TCSEC_ROOT_KEY_LENGTH;
    write_u32(cursor, ordinary->pending_root_version); cursor += 4u;
    write_u64(cursor, ordinary->pending_transaction_id); cursor += 8u;
    write_u16(cursor, (uint16_t)recovery->suite); cursor += 2u;
    memcpy(cursor, recovery->recovery_root, TCSEC_ROOT_KEY_LENGTH); cursor += TCSEC_ROOT_KEY_LENGTH;
    write_u32(cursor, recovery->root_version); cursor += 4u;
    write_u16(cursor, recovery->spi); cursor += 2u;
    memcpy(cursor, recovery->nonce_prefix, TCSEC_NONCE_PREFIX_LENGTH); cursor += TCSEC_NONCE_PREFIX_LENGTH;
    encode_replay(&cursor, &recovery->replay);
    if ((size_t)(cursor - output) != TCSEC_NVM_IMAGE_LENGTH - NVM_TRAILER_LENGTH)
        return TCSEC_INVALID_CONFIGURATION;
    checksum = crc32c(output, (size_t)(cursor - output));
    write_u32(cursor, checksum); cursor += 4u;
    write_u32(cursor, ~checksum);
    *output_length = TCSEC_NVM_IMAGE_LENGTH;
    return TCSEC_OK;
}

tcsec_status_t tcsec_nvm_decode(const uint8_t *encoded,
                                size_t encoded_length,
                                uint32_t minimum_generation,
                                tcsec_nvm_image_t *image) {
    const uint8_t *cursor;
    uint32_t checksum;
    tcsec_nvm_image_t candidate;
    tcsec_ordinary_config_t *ordinary;
    tcsec_recovery_config_t *recovery;
    if (encoded == NULL || image == NULL) return TCSEC_INVALID_ARGUMENT;
    memset(&candidate, 0, sizeof(candidate));
    if (encoded_length != TCSEC_NVM_IMAGE_LENGTH ||
        memcmp(encoded, nvm_magic, sizeof(nvm_magic)) != 0 ||
        read_u16(&encoded[4]) != NVM_VERSION || read_u16(&encoded[6]) != NVM_PAYLOAD_LENGTH)
        return TCSEC_STATE_INTEGRITY_FAILED;
    checksum = crc32c(encoded, encoded_length - NVM_TRAILER_LENGTH);
    if (read_u32(&encoded[encoded_length - 8u]) != checksum ||
        read_u32(&encoded[encoded_length - 4u]) != ~checksum)
        return TCSEC_STATE_INTEGRITY_FAILED;
    candidate.generation = read_u32(&encoded[8]);
    if (candidate.generation == 0u || candidate.generation < minimum_generation)
        return TCSEC_STATE_INTEGRITY_FAILED;
    memcpy(candidate.profile_digest, &encoded[12], TCSEC_NVM_PROFILE_DIGEST_LENGTH);
    if (bytes_all_zero(candidate.profile_digest, sizeof(candidate.profile_digest)))
        return TCSEC_STATE_INTEGRITY_FAILED;
    ordinary = &candidate.config.ordinary;
    recovery = &candidate.config.recovery;
    cursor = &encoded[NVM_HEADER_LENGTH];
    ordinary->spacecraft_id = read_u16(cursor); cursor += 2u;
    ordinary->suite = (tcsec_suite_t)read_u16(cursor); cursor += 2u;
    memcpy(ordinary->operational_root, cursor, TCSEC_ROOT_KEY_LENGTH); cursor += TCSEC_ROOT_KEY_LENGTH;
    ordinary->operational_root_length = TCSEC_ROOT_KEY_LENGTH;
    ordinary->root_version = read_u32(cursor); cursor += 4u;
    ordinary->current_epoch = read_u32(cursor); cursor += 4u;
    ordinary->current_spi = read_u16(cursor); cursor += 2u;
    memcpy(ordinary->nonce_prefix, cursor, TCSEC_NONCE_PREFIX_LENGTH); cursor += TCSEC_NONCE_PREFIX_LENGTH;
    decode_replay(&cursor, &ordinary->replay);
    ordinary->pending_root_present = *cursor++;
    ordinary->pending_suite = (tcsec_suite_t)read_u16(cursor); cursor += 2u;
    if (ordinary->pending_root_present == 0u && !bytes_all_zero(cursor, TCSEC_ROOT_KEY_LENGTH)) {
        zeroize(&candidate, sizeof(candidate));
        return TCSEC_STATE_INTEGRITY_FAILED;
    }
    memcpy(ordinary->pending_operational_root, cursor, TCSEC_ROOT_KEY_LENGTH); cursor += TCSEC_ROOT_KEY_LENGTH;
    ordinary->pending_operational_root_length = ordinary->pending_root_present != 0u ? TCSEC_ROOT_KEY_LENGTH : 0u;
    ordinary->pending_root_version = read_u32(cursor); cursor += 4u;
    ordinary->pending_transaction_id = read_u64(cursor); cursor += 8u;
    recovery->suite = (tcsec_suite_t)read_u16(cursor); cursor += 2u;
    memcpy(recovery->recovery_root, cursor, TCSEC_ROOT_KEY_LENGTH); cursor += TCSEC_ROOT_KEY_LENGTH;
    recovery->recovery_root_length = TCSEC_ROOT_KEY_LENGTH;
    recovery->root_version = read_u32(cursor); cursor += 4u;
    recovery->spi = read_u16(cursor); cursor += 2u;
    memcpy(recovery->nonce_prefix, cursor, TCSEC_NONCE_PREFIX_LENGTH); cursor += TCSEC_NONCE_PREFIX_LENGTH;
    decode_replay(&cursor, &recovery->replay);
    if ((size_t)(cursor - encoded) != encoded_length - NVM_TRAILER_LENGTH ||
        !tcsec_config_valid_internal(&candidate.config)) {
        zeroize(&candidate, sizeof(candidate));
        return TCSEC_INVALID_CONFIGURATION;
    }
    memcpy(image, &candidate, sizeof(*image));
    zeroize(&candidate, sizeof(candidate));
    return TCSEC_OK;
}

tcsec_status_t tcsec_nvm_select_latest(const uint8_t *slot0,
                                       size_t slot0_length,
                                       const uint8_t *slot1,
                                       size_t slot1_length,
                                       uint32_t minimum_generation,
                                       tcsec_nvm_image_t *image,
                                       uint8_t *selected_slot) {
    tcsec_nvm_image_t first;
    tcsec_nvm_image_t second;
    tcsec_status_t first_status;
    tcsec_status_t second_status;
    if (image == NULL || selected_slot == NULL) return TCSEC_INVALID_ARGUMENT;
    memset(&first, 0, sizeof(first)); memset(&second, 0, sizeof(second));
    first_status = tcsec_nvm_decode(slot0, slot0_length, minimum_generation, &first);
    second_status = tcsec_nvm_decode(slot1, slot1_length, minimum_generation, &second);
    if (first_status != TCSEC_OK && second_status != TCSEC_OK)
        return TCSEC_STATE_INTEGRITY_FAILED;
    if (first_status == TCSEC_OK && second_status == TCSEC_OK &&
        first.generation == second.generation &&
        (slot0_length != slot1_length || memcmp(slot0, slot1, slot0_length) != 0)) {
        zeroize(&first, sizeof(first)); zeroize(&second, sizeof(second));
        return TCSEC_STATE_INTEGRITY_FAILED;
    }
    if (second_status == TCSEC_OK &&
        (first_status != TCSEC_OK || second.generation > first.generation)) {
        memcpy(image, &second, sizeof(*image)); *selected_slot = 1u;
    } else {
        memcpy(image, &first, sizeof(*image)); *selected_slot = 0u;
    }
    zeroize(&first, sizeof(first)); zeroize(&second, sizeof(second));
    return TCSEC_OK;
}
