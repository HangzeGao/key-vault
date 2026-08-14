#include "tc_security.h"
#include "tc_security_kdf.h"
#include "gcm.h"
#include "hctr.h"
#include "sm4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_CAPACITY 16384u
#define VALUE_CAPACITY 2048u
#define FIELD_COUNT 18u

int tcsec_test_sm4_cmac(const uint8_t key[16], const uint8_t *message,
                        size_t length, uint8_t tag[16]);

typedef struct {
    const char *id;
    const char *algorithm;
    uint8_t key[VALUE_CAPACITY]; size_t key_length;
    uint8_t nonce[VALUE_CAPACITY]; size_t nonce_length;
    uint8_t aad[VALUE_CAPACITY]; size_t aad_length;
    uint8_t plaintext[VALUE_CAPACITY]; size_t plaintext_length;
    uint8_t ciphertext[VALUE_CAPACITY]; size_t ciphertext_length;
    uint8_t tag[VALUE_CAPACITY]; size_t tag_length;
    uint8_t label[VALUE_CAPACITY]; size_t label_length;
    uint8_t context[VALUE_CAPACITY]; size_t context_length;
    uint8_t output[VALUE_CAPACITY]; size_t output_length;
} vector_t;

static int hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode(const char *text, uint8_t *output, size_t capacity, size_t *length) {
    size_t text_length;
    size_t index;
    if (strcmp(text, "-") == 0) { *length = 0u; return 1; }
    text_length = strlen(text);
    if ((text_length & 1u) != 0u || text_length / 2u > capacity) return 0;
    for (index = 0u; index < text_length; index += 2u) {
        int high = hex_value(text[index]);
        int low = hex_value(text[index + 1u]);
        if (high < 0 || low < 0) return 0;
        output[index / 2u] = (uint8_t)((high << 4) | low);
    }
    *length = text_length / 2u;
    return 1;
}

static int parse(char *line, vector_t *vector) {
    char *fields[FIELD_COUNT];
    size_t count = 0u;
    char *cursor = line;
    memset(vector, 0, sizeof(*vector));
    while (count < FIELD_COUNT) {
        char *tab;
        fields[count++] = cursor;
        tab = strchr(cursor, '\t');
        if (tab == NULL) break;
        *tab = '\0';
        cursor = tab + 1;
    }
    if (count != FIELD_COUNT || strchr(fields[FIELD_COUNT - 1u], '\t') != NULL ||
        strcmp(fields[4], "VERIFY") != 0 || strcmp(fields[14], "OK") != 0 ||
        fields[15][0] == '\0' || fields[16][0] == '\0') return 0;
    vector->id = fields[0]; vector->algorithm = fields[3];
    return decode(fields[5], vector->key, sizeof(vector->key), &vector->key_length) &&
           decode(fields[6], vector->nonce, sizeof(vector->nonce), &vector->nonce_length) &&
           decode(fields[7], vector->aad, sizeof(vector->aad), &vector->aad_length) &&
           decode(fields[8], vector->plaintext, sizeof(vector->plaintext), &vector->plaintext_length) &&
           decode(fields[9], vector->ciphertext, sizeof(vector->ciphertext), &vector->ciphertext_length) &&
           decode(fields[10], vector->tag, sizeof(vector->tag), &vector->tag_length) &&
           decode(fields[11], vector->label, sizeof(vector->label), &vector->label_length) &&
           decode(fields[12], vector->context, sizeof(vector->context), &vector->context_length) &&
           decode(fields[13], vector->output, sizeof(vector->output), &vector->output_length);
}

static int test_block(const vector_t *vector) {
    tcsec_sm4_key_t key;
    uint8_t output[16];
    int ok;
    if (vector->key_length != 16u || vector->plaintext_length != 16u ||
        vector->ciphertext_length != 16u || tcsec_sm4_key_init(&key, vector->key) != 0) return 0;
    tcsec_sm4_encrypt_with_key(&key, vector->plaintext, output);
    ok = memcmp(output, vector->ciphertext, 16u) == 0;
    tcsec_sm4_decrypt_with_key(&key, vector->ciphertext, output);
    ok = ok && memcmp(output, vector->plaintext, 16u) == 0;
    tcsec_sm4_key_clear(&key);
    return ok;
}

static int test_cmac(const vector_t *vector) {
    uint8_t tag[16];
    return vector->key_length == 16u && vector->tag_length == 16u &&
           tcsec_test_sm4_cmac(vector->key, vector->plaintext,
                               vector->plaintext_length, tag) == 0 &&
           memcmp(tag, vector->tag, 16u) == 0;
}

static int test_gcm(const vector_t *vector) {
    uint8_t plaintext[VALUE_CAPACITY];
    if (vector->key_length != 16u || vector->nonce_length != TCSEC_GCM_NONCE_LENGTH ||
        vector->tag_length != TCSEC_GCM_TAG_LENGTH ||
        vector->ciphertext_length != vector->plaintext_length) return 0;
    if (tcsec_gcm_open(TCSEC_SUITE_SM4_GCM, vector->key, vector->nonce,
                       vector->aad, vector->aad_length, vector->ciphertext,
                       vector->ciphertext_length, vector->tag, plaintext) != 0) return 0;
    return memcmp(plaintext, vector->plaintext, vector->plaintext_length) == 0;
}

static int test_hctr(const vector_t *vector) {
    uint8_t ciphertext[VALUE_CAPACITY];
    uint8_t plaintext[VALUE_CAPACITY];
    if (vector->key_length != TCSEC_HCTR_WORKING_KEY_LENGTH ||
        vector->nonce_length != TCSEC_HCTR_TWEAK_LENGTH ||
        vector->plaintext_length < 16u ||
        vector->ciphertext_length != vector->plaintext_length) return 0;
    return tcsec_sm4_hctr_encrypt(vector->key, vector->nonce, vector->plaintext,
                                  ciphertext, vector->plaintext_length) == 0 &&
           memcmp(ciphertext, vector->ciphertext, vector->ciphertext_length) == 0 &&
           tcsec_sm4_hctr_decrypt(vector->key, vector->nonce, vector->ciphertext,
                                  plaintext, vector->ciphertext_length) == 0 &&
           memcmp(plaintext, vector->plaintext, vector->plaintext_length) == 0;
}

static int test_kdf(const vector_t *vector) {
    uint8_t output[TCSEC_HCTR_WORKING_KEY_LENGTH];
    if (vector->key_length != TCSEC_SM4_KEY_LENGTH) return 0;
    if (vector->output_length == TCSEC_HCTR_WORKING_KEY_LENGTH) {
        return vector->label_length == 10u && memcmp(vector->label, "TC-TRAFFIC", 10u) == 0 &&
               vector->context_length == 15u &&
               tcsec_derive_ordinary_key(vector->key, vector->key_length,
                   (uint16_t)((vector->context[0] << 8) | vector->context[1]),
                   TCSEC_SUITE_SM4_HCTR,
                   (uint16_t)((vector->context[5] << 8) | vector->context[6]),
                   ((uint32_t)vector->context[7] << 24) | ((uint32_t)vector->context[8] << 16) |
                   ((uint32_t)vector->context[9] << 8) | vector->context[10],
                   ((uint32_t)vector->context[11] << 24) | ((uint32_t)vector->context[12] << 16) |
                   ((uint32_t)vector->context[13] << 8) | vector->context[14],
                   output, sizeof(output)) == 0 &&
               memcmp(output, vector->output, vector->output_length) == 0;
    }
    if (vector->output_length == TCSEC_SM4_KEY_LENGTH) {
        return vector->label_length == 15u && memcmp(vector->label, "TC-RECOVERY-GCM", 15u) == 0 &&
               vector->context_length == 10u &&
               tcsec_derive_recovery_key(vector->key, vector->key_length,
                   (uint16_t)((vector->context[0] << 8) | vector->context[1]),
                   TCSEC_SUITE_SM4_GCM,
                   (uint16_t)((vector->context[4] << 8) | vector->context[5]),
                   ((uint32_t)vector->context[6] << 24) | ((uint32_t)vector->context[7] << 16) |
                   ((uint32_t)vector->context[8] << 8) | vector->context[9],
                   output, sizeof(output)) == 0 &&
               memcmp(output, vector->output, vector->output_length) == 0;
    }
    return 0;
}

int main(int argc, char **argv) {
    FILE *file;
    char line[LINE_CAPACITY];
    unsigned block_count = 0u, cmac_count = 0u, gcm_count = 0u, hctr_count = 0u, kdf_count = 0u;
    if (argc != 2) { fprintf(stderr, "expected external vector path\n"); return 2; }
    file = fopen(argv[1], "rb");
    if (file == NULL) { fprintf(stderr, "cannot open external vectors\n"); return 2; }
    while (fgets(line, sizeof(line), file) != NULL) {
        vector_t vector;
        int ok = 0;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;
        if (!parse(line, &vector)) { fprintf(stderr, "invalid external vector row\n"); fclose(file); return 1; }
        if (strcmp(vector.algorithm, "SM4_BLOCK") == 0) { ok = test_block(&vector); block_count++; }
        else if (strcmp(vector.algorithm, "SM4_CMAC") == 0) { ok = test_cmac(&vector); cmac_count++; }
        else if (strcmp(vector.algorithm, "SM4_GCM") == 0) { ok = test_gcm(&vector); gcm_count++; }
        else if (strcmp(vector.algorithm, "SM4_HCTR") == 0) { ok = test_hctr(&vector); hctr_count++; }
        else if (strcmp(vector.algorithm, "SP800_108_SM4_CMAC") == 0) { ok = test_kdf(&vector); kdf_count++; }
        if (!ok) { fprintf(stderr, "external vector failed: %s\n", vector.id); fclose(file); return 1; }
    }
    fclose(file);
    if (block_count < 5u || cmac_count < 8u || gcm_count < 6u || hctr_count < 7u || kdf_count < 2u) {
        fprintf(stderr, "external vector coverage is incomplete\n"); return 1;
    }
    printf("External pyca/cryptography/RFC vectors passed: block=%u cmac=%u gcm=%u hctr=%u kdf=%u\n",
           block_count, cmac_count, gcm_count, hctr_count, kdf_count);
    return 0;
}
