#include "downlink_security.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "downlink check failed at line %d\n", __LINE__); exit(1); } } while (0)

static int all_bytes(const uint8_t *bytes, size_t length, uint8_t value) {
    size_t index;
    for (index = 0u; index < length; ++index) if (bytes[index] != value) return 0;
    return 1;
}

static size_t decode(const char *hex, uint8_t *output, size_t capacity) {
    size_t length = strlen(hex), index;
    CHECK(length % 2u == 0u && length / 2u <= capacity);
    for (index = 0u; index < length; ++index) CHECK(strchr("0123456789abcdef", hex[index]) != NULL);
    for (index = 0u; index < length / 2u; ++index) {
        unsigned byte;
        CHECK(sscanf(hex + 2u * index, "%2x", &byte) == 1);
        output[index] = (uint8_t)byte;
    }
    return length / 2u;
}

static void test_vectors(const char *path, FILE *flight_output) {
    FILE *file = fopen(path, "r");
    char line[8192];
    unsigned normative = 0u, independent = 0u;
    CHECK(file != NULL);
    while (fgets(line, sizeof(line), file) != NULL) {
        char *fields[18], *cursor = line;
        uint8_t key[32], plaintext[880], expected[880], output[882], inplace[880];
        size_t field, length;
        if (line[0] == '#') continue;
        CHECK(strchr(line, '\n') != NULL);
        line[strcspn(line, "\r\n")] = '\0';
        for (field = 0u; field < 18u; ++field) {
            char *tab;
            fields[field] = cursor;
            tab = strchr(cursor, '\t');
            if (field == 17u) { CHECK(tab == NULL); break; }
            CHECK(tab != NULL);
            *tab = '\0'; cursor = tab + 1;
        }
        CHECK(strcmp(fields[3], "AES_256_ECB") == 0 && strcmp(fields[4], "VERIFY") == 0 &&
              strcmp(fields[14], "OK") == 0 && strcmp(fields[15], "pyca-cryptography") == 0 &&
              strcmp(fields[16], "50.0.2/OpenSSL-4.0.3") == 0);
        CHECK(decode(fields[5], key, sizeof(key)) == 32u);
        length = decode(fields[8], plaintext, sizeof(plaintext));
        CHECK(decode(fields[9], expected, sizeof(expected)) == length);
        if (strcmp(fields[1], "NORMATIVE") == 0) {
            size_t offset;
            CHECK(length == 16u); ++normative;
            for (offset = 16u; offset < 880u; offset += 16u) {
                memcpy(plaintext + offset, plaintext, 16u);
                memcpy(expected + offset, expected, 16u);
            }
        } else { CHECK(strcmp(fields[1], "INDEPENDENT") == 0 && length == 880u); ++independent; }
        memset(output, 0xa5, sizeof(output));
        CHECK(dlsec_encrypt_data(key, sizeof(key), plaintext, sizeof(plaintext), output + 1u, 881u) == DLSEC_OK);
        CHECK(output[0] == 0xa5u && output[881] == 0xa5u);
        CHECK(memcmp(output + 1u, expected, 880u) == 0);
        if (flight_output != NULL) CHECK(fwrite(output + 1u, 1u, 880u, flight_output) == 880u);
        memcpy(inplace, plaintext, sizeof(inplace));
        CHECK(dlsec_encrypt_data(key, sizeof(key), inplace, sizeof(inplace), inplace, sizeof(inplace)) == DLSEC_OK);
        CHECK(memcmp(inplace, expected, sizeof(inplace)) == 0);
        /* A second call with the same key/plaintext is permitted: ECB has no replay state. */
        CHECK(dlsec_encrypt_data(key, sizeof(key), plaintext, sizeof(plaintext), output + 1u, 880u) == DLSEC_OK);
        CHECK(memcmp(output + 1u, expected, 880u) == 0);
    }
    CHECK(!ferror(file) && fclose(file) == 0 && normative == 4u && independent == 379u);
    printf("AES downlink C vectors passed: normative=%u independent=%u\n", normative, independent);
}

static void test_invalid(void) {
    uint8_t key[32] = {0}, input[880] = {0}, output[882], overlap[1000];
    size_t length;
    for (length = 0u; length < 40u; ++length) {
        if (length == 32u) continue;
        memset(output, 0xa5, sizeof(output));
        CHECK(dlsec_encrypt_data(key, length, input, 880u, output + 1u, 881u) == DLSEC_INVALID_ARGUMENT);
        CHECK(all_bytes(output + 1u, 880u, 0u) && output[0] == 0xa5u && output[881] == 0xa5u);
    }
    for (length = 0u; length <= 1024u; ++length) {
        if (length == 880u) continue;
        memset(output, 0xa5, sizeof(output));
        CHECK(dlsec_encrypt_data(key, 32u, input, length, output + 1u, 880u) == DLSEC_INVALID_ARGUMENT);
        CHECK(all_bytes(output + 1u, 880u, 0u) && output[0] == 0xa5u && output[881] == 0xa5u);
    }
    for (length = 0u; length < 880u; ++length) {
        memset(output, 0xa5, sizeof(output));
        CHECK(dlsec_encrypt_data(key, 32u, input, 880u, output + 1u, length) == DLSEC_OUTPUT_TOO_SMALL);
        CHECK(all_bytes(output + 1u, length, 0u) && output[0] == 0xa5u && output[length + 1u] == 0xa5u);
    }
    memset(output, 0xa5, sizeof(output));
    CHECK(dlsec_encrypt_data(NULL, 32u, input, 880u, output, 880u) == DLSEC_INVALID_ARGUMENT);
    CHECK(all_bytes(output, 880u, 0u));
    memset(output, 0xa5, sizeof(output));
    CHECK(dlsec_encrypt_data(key, 32u, NULL, 880u, output, 880u) == DLSEC_INVALID_ARGUMENT);
    CHECK(all_bytes(output, 880u, 0u));
    CHECK(dlsec_encrypt_data(key, 32u, input, 880u, NULL, 880u) == DLSEC_INVALID_ARGUMENT);
    CHECK(dlsec_encrypt_data(NULL, 0u, NULL, 0u, NULL, 0u) == DLSEC_INVALID_ARGUMENT);
    /* Partial overlap in both directions; no write outside the declared output. */
    for (length = 1u; length <= 32u; ++length) {
        memset(overlap, 0xa5, sizeof(overlap));
        CHECK(dlsec_encrypt_data(key, 32u, overlap, 880u, overlap + length, 880u) == DLSEC_INVALID_ARGUMENT);
        CHECK(all_bytes(overlap, length, 0xa5u) && all_bytes(overlap + length, 880u, 0u) && overlap[length + 880u] == 0xa5u);
        memset(overlap, 0xa5, sizeof(overlap));
        CHECK(dlsec_encrypt_data(key, 32u, overlap + length, 880u, overlap, 880u) == DLSEC_INVALID_ARGUMENT);
        CHECK(all_bytes(overlap, 880u, 0u) && all_bytes(overlap + 880u, length, 0xa5u));
    }
    memset(overlap, 0xa5, sizeof(overlap));
    CHECK(dlsec_encrypt_data(overlap, 32u, input, 880u, overlap, 880u) == DLSEC_INVALID_ARGUMENT);
    CHECK(all_bytes(overlap, 880u, 0u) && overlap[880] == 0xa5u);
    memset(overlap, 0xa5, sizeof(overlap));
    CHECK(dlsec_encrypt_data(overlap + 879u, 32u, input, 880u, overlap, 880u) == DLSEC_INVALID_ARGUMENT);
    CHECK(all_bytes(overlap, 880u, 0u) && all_bytes(overlap + 880u, 31u, 0xa5u));
    memset(overlap, 0xa5, sizeof(overlap));
    CHECK(dlsec_encrypt_data(overlap, 32u, input, 880u, overlap + 31u, 880u) == DLSEC_INVALID_ARGUMENT);
    CHECK(all_bytes(overlap, 31u, 0xa5u) && all_bytes(overlap + 31u, 880u, 0u));
    CHECK(dlsec_encrypt_data(key, SIZE_MAX, input, SIZE_MAX, output, sizeof(output)) == DLSEC_INVALID_ARGUMENT);
}

static uint32_t random_word(uint32_t *seed) {
    *seed ^= *seed << 13; *seed ^= *seed >> 17; *seed ^= *seed << 5;
    return *seed;
}

static void fuzz_smoke(void) {
    uint8_t key[40], input[1024], output[1026];
    uint32_t seed = 0x4b564c54u;
    size_t iteration, index;
    for (iteration = 0u; iteration < 4096u; ++iteration) {
        size_t key_length = random_word(&seed) % 41u;
        size_t length = random_word(&seed) % 1025u;
        size_t capacity = random_word(&seed) % 1025u;
        dlsec_status_t status;
        for (index = 0u; index < sizeof(key); ++index) key[index] = (uint8_t)random_word(&seed);
        for (index = 0u; index < sizeof(input); ++index) input[index] = (uint8_t)random_word(&seed);
        if (iteration % 64u == 0u) { key_length = 32u; length = 880u; capacity = 880u; }
        memset(output, 0xa5, sizeof(output));
        status = dlsec_encrypt_data(key, key_length, input, length, output + 1u, capacity);
        if (key_length != 32u || length != 880u) CHECK(status == DLSEC_INVALID_ARGUMENT);
        else if (capacity < 880u) CHECK(status == DLSEC_OUTPUT_TOO_SMALL);
        else CHECK(status == DLSEC_OK);
        if (status != DLSEC_OK) CHECK(all_bytes(output + 1u, capacity < 880u ? capacity : 880u, 0u));
        CHECK(output[0] == 0xa5u && output[capacity + 1u] == 0xa5u);
    }
    puts("AES downlink C bounded fuzz passed: seed=0x4b564c54 iterations=4096 crashes=0");
}

int main(int argc, char **argv) {
    FILE *output = NULL;
    CHECK(argc == 2 || argc == 3);
    if (argc == 3) { output = fopen(argv[2], "wb"); CHECK(output != NULL); }
    test_vectors(argv[1], output);
    if (output != NULL) CHECK(fclose(output) == 0);
    test_invalid();
    fuzz_smoke();
    return 0;
}
