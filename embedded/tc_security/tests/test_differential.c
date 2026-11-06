#include "tc_security.h"
#include "tc_security_kdf.h"
#include "gcm.h"
#include "sm4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_CAPACITY 4096u

static int nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode(const char *text, uint8_t *output, size_t capacity, size_t *length) {
    size_t size = strlen(text);
    size_t index;
    if ((size & 1u) != 0u || size / 2u > capacity) return 0;
    for (index = 0u; index < size; index += 2u) {
        int high = nibble(text[index]);
        int low = nibble(text[index + 1u]);
        if (high < 0 || low < 0) return 0;
        output[index / 2u] = (uint8_t)((high << 4) | low);
    }
    *length = size / 2u;
    return 1;
}

static int ordinary(char **fields) {
    uint8_t root[16], nonce[12], plain[1024], encrypted[1024], tag[4], out[1024], key[16];
    size_t rn, nn, pn, cn, tn;
    uint16_t scid = (uint16_t)strtoul(fields[2], NULL, 16),
             spi = (uint16_t)strtoul(fields[3], NULL, 16);
    uint32_t epoch = (uint32_t)strtoul(fields[4], NULL, 16),
             version = (uint32_t)strtoul(fields[5], NULL, 16);
    return decode(fields[1], root, 16, &rn) && rn == 16 && decode(fields[6], nonce, 12, &nn) &&
           nn == 12 && decode(fields[7], plain, 1024, &pn) &&
           decode(fields[8], encrypted, 1024, &cn) && cn == pn && decode(fields[9], tag, 4, &tn) &&
           tn == 4 &&
           tcsec_derive_ordinary_key(root, rn, scid, TCSEC_SUITE_SM4_GCM_32, spi, epoch, version,
                                     key, 16) == 0 &&
           tcsec_gcm_open_short(key, nonce, (const uint8_t *)"TC-AAD!", 7, encrypted, cn, tag,
                                out) == 0 &&
           memcmp(out, plain, pn) == 0;
}

static int recovery(char **fields) {
    uint8_t root[16], expected[16], actual[16];
    size_t root_length, expected_length;
    uint16_t spacecraft = (uint16_t)strtoul(fields[2], NULL, 16);
    uint16_t spi = (uint16_t)strtoul(fields[3], NULL, 16);
    uint32_t version = (uint32_t)strtoul(fields[4], NULL, 16);
    return decode(fields[1], root, sizeof(root), &root_length) && root_length == sizeof(root) &&
           decode(fields[5], expected, sizeof(expected), &expected_length) && expected_length == sizeof(expected) &&
           tcsec_derive_recovery_key(root, root_length, spacecraft, TCSEC_SUITE_SM4_GCM,
                                     spi, version, actual, sizeof(actual)) == 0 &&
           memcmp(actual, expected, sizeof(expected)) == 0;
}

int main(int argc, char **argv) {
    FILE *file;
    char line[LINE_CAPACITY];
    size_t cases = 0u;
    tcsec_sm4_key_t diagnostic;
    uint8_t zero[16] = {0u};
    const char *backend;
    if (argc != 2 || (file = fopen(argv[1], "rb")) == NULL) return 1;
    if (tcsec_sm4_key_init(&diagnostic, zero) != 0) return 1;
    backend = tcsec_sm4_backend_name(&diagnostic);
    while (fgets(line, sizeof(line), file) != NULL) {
        char *fields[10];
        char *token = strtok(line, " \r\n");
        size_t count = 0u;
        while (token != NULL && count < 10u) {
            fields[count++] = token;
            token = strtok(NULL, " \r\n");
        }
        if ((count == 10u && strcmp(fields[0], "O") == 0 && ordinary(fields)) ||
            (count == 6u && strcmp(fields[0], "R") == 0 && recovery(fields))) {
            cases++;
            continue;
        }
        fclose(file);
        return 1;
    }
    fclose(file);
    tcsec_sm4_key_clear(&diagnostic);
    if (cases == 0u) return 1;
    printf("Go-C differential passed: backend=%s cases=%lu\n", backend, (unsigned long)cases);
    return 0;
}
