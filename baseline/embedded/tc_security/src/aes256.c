#include "aes256.h"

#include <string.h>

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rcon[15] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d
};

static uint8_t xtime(uint8_t value) {
    return (uint8_t)((value << 1) ^ ((value & 0x80u) ? 0x1bu : 0u));
}

static uint8_t mul3(uint8_t value) {
    return (uint8_t)(xtime(value) ^ value);
}

static void zero_memory(void *memory, size_t length) {
    volatile uint8_t *cursor = (volatile uint8_t *)memory;
    while (length-- != 0u) {
        *cursor++ = 0u;
    }
}

static void expand_key(const uint8_t key[32], uint8_t round_keys[240]) {
    uint32_t generated = 32u;
    uint8_t rcon_index = 1u;
    uint8_t temporary[4];
    uint32_t index;

    memcpy(round_keys, key, 32u);
    while (generated < 240u) {
        memcpy(temporary, &round_keys[generated - 4u], 4u);
        if ((generated % 32u) == 0u) {
            uint8_t first = temporary[0];
            temporary[0] = sbox[temporary[1]];
            temporary[1] = sbox[temporary[2]];
            temporary[2] = sbox[temporary[3]];
            temporary[3] = sbox[first];
            temporary[0] ^= rcon[rcon_index++];
        } else if ((generated % 32u) == 16u) {
            temporary[0] = sbox[temporary[0]];
            temporary[1] = sbox[temporary[1]];
            temporary[2] = sbox[temporary[2]];
            temporary[3] = sbox[temporary[3]];
        }
        for (index = 0u; index < 4u; ++index) {
            round_keys[generated] = (uint8_t)(round_keys[generated - 32u] ^ temporary[index]);
            ++generated;
        }
    }
    zero_memory(temporary, sizeof(temporary));
}

static void add_round_key(uint8_t state[16], const uint8_t *round_key) {
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        state[index] ^= round_key[index];
    }
}

static void sub_bytes(uint8_t state[16]) {
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        state[index] = sbox[state[index]];
    }
}

static void shift_rows(uint8_t state[16]) {
    uint8_t temporary;

    temporary = state[1];
    state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temporary;

    temporary = state[2]; state[2] = state[10]; state[10] = temporary;
    temporary = state[6]; state[6] = state[14]; state[14] = temporary;

    temporary = state[15];
    state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temporary;
}

static void mix_columns(uint8_t state[16]) {
    uint32_t column;
    for (column = 0u; column < 4u; ++column) {
        uint32_t offset = column * 4u;
        uint8_t a0 = state[offset];
        uint8_t a1 = state[offset + 1u];
        uint8_t a2 = state[offset + 2u];
        uint8_t a3 = state[offset + 3u];
        state[offset]      = (uint8_t)(xtime(a0) ^ mul3(a1) ^ a2 ^ a3);
        state[offset + 1u] = (uint8_t)(a0 ^ xtime(a1) ^ mul3(a2) ^ a3);
        state[offset + 2u] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ mul3(a3));
        state[offset + 3u] = (uint8_t)(mul3(a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

static void encrypt_block(const uint8_t input[16], uint8_t output[16], const uint8_t round_keys[240]) {
    uint8_t state[16];
    uint32_t round;

    memcpy(state, input, 16u);
    add_round_key(state, round_keys);
    for (round = 1u; round < 14u; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &round_keys[round * 16u]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[14u * 16u]);
    memcpy(output, state, 16u);
    zero_memory(state, sizeof(state));
}

static int increment_counter32(uint8_t counter[16]) {
    int index;
    for (index = 15; index >= 12; --index) {
        counter[index] = (uint8_t)(counter[index] + 1u);
        if (counter[index] != 0u) {
            return 0;
        }
    }
    return -1;
}

int tcsec_aes256_encrypt_block(const uint8_t key[32],
                               const uint8_t input[16],
                               uint8_t output[16]) {
    uint8_t round_keys[240];
    if (key == NULL || input == NULL || output == NULL) {
        return -1;
    }
    expand_key(key, round_keys);
    encrypt_block(input, output, round_keys);
    zero_memory(round_keys, sizeof(round_keys));
    return 0;
}

int tcsec_aes256_ctr_xor(const uint8_t key[32],
                         const uint8_t initial_counter[16],
                         const uint8_t *input,
                         uint8_t *output,
                         size_t length) {
    uint8_t round_keys[240];
    uint8_t counter[16];
    uint8_t stream[16];
    size_t offset = 0u;

    if (key == NULL || initial_counter == NULL ||
        (length != 0u && (input == NULL || output == NULL))) {
        return -1;
    }
    expand_key(key, round_keys);
    memcpy(counter, initial_counter, sizeof(counter));
    while (offset < length) {
        size_t block_length = length - offset;
        size_t index;
        if (block_length > 16u) {
            block_length = 16u;
        }
        encrypt_block(counter, stream, round_keys);
        for (index = 0u; index < block_length; ++index) {
            output[offset + index] = (uint8_t)(input[offset + index] ^ stream[index]);
        }
        offset += block_length;
        if (offset < length && increment_counter32(counter) != 0) {
            zero_memory(round_keys, sizeof(round_keys));
            zero_memory(counter, sizeof(counter));
            zero_memory(stream, sizeof(stream));
            return -2;
        }
    }
    zero_memory(round_keys, sizeof(round_keys));
    zero_memory(counter, sizeof(counter));
    zero_memory(stream, sizeof(stream));
    return 0;
}
