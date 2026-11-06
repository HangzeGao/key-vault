/* Host process harness with public TEST ONLY roots. Never a flight driver. */
#define _POSIX_C_SOURCE 200809L
#define main ordinary_test_main
#include "test_tc_security.c"
#undef main
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>

typedef struct {
    tcsec_config_t config;
    uint32_t checksum;
} disk_record_t;
typedef struct {
    const char *path;
    const char *fault;
    unsigned commit_calls;
    unsigned budget_calls;
} disk_store_t;

static tcsec_status_t disk_load(void *user, tcsec_config_t *out) {
    const disk_store_t *store = user;
    disk_record_t record = {0};
    FILE *file = fopen(store->path, "rb");
    int valid;
    if (file == NULL) return TCSEC_STATE_INTEGRITY_FAILED;
    valid = fread(&record, sizeof(record), 1, file) == 1 && fgetc(file) == EOF &&
            record.checksum == model_checksum(&record.config);
    fclose(file);
    if (valid) *out = record.config;
    memset(&record, 0, sizeof(record));
    return valid ? TCSEC_OK : TCSEC_STATE_INTEGRITY_FAILED;
}

static tcsec_commit_result_t disk_commit(void *user, const tcsec_commit_t *change) {
    disk_store_t *store = user;
    storage_fixture_t candidate = {0};
    disk_record_t record = {0};
    tcsec_commit_result_t result = TCSEC_COMMIT_PERSISTENCE_FAILED;
    char temporary[4096], directory[4096], *slash;
    FILE *file;
    int written, directory_fd, partial;
    const char *fault = store->fault;
    int quota = change->kind == TCSEC_COMMIT_AUTH_BUDGET;
    if (quota)
        ++store->budget_calls;
    else
        ++store->commit_calls;
    if (strncmp(fault, "budget-", 7) == 0)
        fault = quota ? fault + 7 : "none";
    else if (quota)
        fault = "none";
    /* These exits model an abruptly lost flight process, not a returned error. */
    if (strcmp(fault, "crash-before") == 0)
        _exit(86);
    if (strcmp(fault, "before") == 0)
        goto cleanup;
    if (disk_load(store, &candidate.saved) != TCSEC_OK ||
        commit_storage(&candidate, change) != TCSEC_COMMIT_NEW) {
        result = TCSEC_COMMIT_REJECTED;
        goto cleanup;
    }
    record.config = candidate.saved;
    record.checksum = model_checksum(&record.config);
    if (snprintf(temporary, sizeof(temporary), "%s.candidate", store->path) >= (int)sizeof(temporary) ||
        snprintf(directory, sizeof(directory), "%s", store->path) >= (int)sizeof(directory)) {
        result = TCSEC_COMMIT_REJECTED;
        goto cleanup;
    }
    file = fopen(temporary, "wb");
    if (file == NULL) goto cleanup;
    partial = strcmp(fault, "partial") == 0 || strcmp(fault, "crash-partial") == 0;
    written = fwrite(&record, partial ? sizeof(record) / 2u : sizeof(record), 1, file) == 1;
    if (fflush(file) != 0 || fsync(fileno(file)) != 0) written = 0;
    if (fclose(file) != 0) written = 0;
    if (strcmp(fault, "crash-partial") == 0 && written)
        _exit(87);
    if (partial || !written || rename(temporary, store->path) != 0) goto cleanup;
    result = TCSEC_COMMIT_UNCERTAIN;
    slash = strrchr(directory, '/');
    if (slash == NULL) goto cleanup;
    *slash = '\0';
    directory_fd = open(directory, O_RDONLY);
    if (directory_fd < 0) goto cleanup;
    written = fsync(directory_fd) == 0;
    close(directory_fd);
    if (strcmp(fault, "crash-after") == 0 && written)
        _exit(88);
    if (written && strcmp(fault, "after") != 0)
        result = TCSEC_COMMIT_NEW;
cleanup:
    memset(&record, 0, sizeof(record));
    memset(&candidate, 0, sizeof(candidate));
    return result;
}

static void print_hex(const uint8_t *data, size_t length) {
    size_t index;
    for (index = 0; index < length; ++index) printf("%02x", data[index]);
}

static void reply(tcsec_status_t status, const tcsec_context_t *context,
                  const disk_store_t *store, const tcsec_result_t *result,
                  const uint8_t *output, size_t capacity) {
    tcsec_runtime_status_t runtime = {0};
    tcsec_status_t diagnostic = tcsec_get_runtime_status(context, &runtime);
    size_t index, length = result != NULL ? result->plaintext_length : 0;
    int cleared = 1;
    for (index = 0; index < capacity; ++index) if (output[index] != 0) cleared = 0;
    printf("{\"status\":\"%s\",\"length\":%lu,\"cleared\":%s,\"plaintext\":\"",
           tcsec_status_string(status), (unsigned long)length, cleared ? "true" : "false");
    print_hex(output, length);
    printf("\",\"commit_calls\":%u,\"diagnostic\":\"%s\",\"current_spi\":%u,"
           "\"next_spi\":%u,\"recovery_spi\":%u,\"epoch\":%" PRIu32 ",\"root_version\":%" PRIu32
           ",\"pending\":%s,\"paused\":%s,\"receive_count\":%" PRIu64 ",\"profile_digest\":\"",
           store->commit_calls, tcsec_status_string(diagnostic), runtime.current_spi,
           runtime.next_spi, runtime.recovery_spi, runtime.security_epoch, runtime.root_version,
           runtime.pending_root_present ? "true" : "false", runtime.reception_paused ? "true" : "false",
           runtime.receive_count);
    print_hex(runtime.profile_digest, sizeof(runtime.profile_digest));
    printf("\",\"current_auth_used\":%u,\"next_auth_used\":%u,\"budget_calls\":%u}\n",
           runtime.current_auth_used, runtime.next_auth_used, store->budget_calls);
    fflush(stdout);
}

int main(int argc, char **argv) {
    vector_t vector;
    disk_store_t store;
    tcsec_context_t context = {0};
    tcsec_callbacks_t callbacks = {0};
    tcsec_result_t result = {0};
    tcsec_status_t status;
    /* One excess byte allows the real receiver to reject overlong input. */
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH + 1u], output[TCSEC_MAX_FRAME_LENGTH];
    char line[8192], fault[32], encoded[4096];
    size_t length;
    if (argc != 4 || !load_vector(argv[1], &vector)) return 2;
    if (strcmp(argv[3], "commission") == 0) {
        disk_record_t record = {0};
        FILE *file = fopen(argv[2], "wbx");
        int written;
        if (file == NULL) return 3;
        if (vector.suite == TCSEC_SUITE_SM4_GCM) recovery_config(&record.config, &vector);
        else ordinary_config(&record.config, &vector);
        record.checksum = model_checksum(&record.config);
        written = fwrite(&record, sizeof(record), 1, file) == 1;
        if (fflush(file) != 0 || fsync(fileno(file)) != 0) written = 0;
        if (fclose(file) != 0) written = 0;
        memset(&record, 0, sizeof(record));
        return written ? 0 : 4;
    }
    if (strcmp(argv[3], "inspect") == 0) {
        disk_record_t record = {0};
        disk_store_t inspection = {.path = argv[2]};
        if (disk_load(&inspection, &record.config) != TCSEC_OK)
            return 10;
        /* Compare root/replay/business state independently from burned authentication quota. */
        record.config.ordinary.current_auth_used = 0;
        record.config.ordinary.next_auth_used = 0;
        record.checksum = model_checksum(&record.config);
        return fwrite(&record, sizeof(record), 1, stdout) == 1 ? 0 : 11;
    }
    if (strcmp(argv[3], "session") != 0) return 5;
    store.path = argv[2];
    store.fault = "none";
    store.commit_calls = 0;
    store.budget_calls = 0;
    callbacks.load_state = disk_load; callbacks.commit_state = disk_commit;
    callbacks.user_context = &store;
    status = tcsec_init(&context, &callbacks);
    reply(status, &context, &store, NULL, NULL, 0);
    while (fgets(line, sizeof(line), stdin) != NULL) {
        if (strcmp(line, "reset\n") == 0) {
            status = tcsec_reset(&context);
            reply(status, &context, &store, NULL, NULL, 0);
        } else {
            static const char *faults[] = {"none",
                                           "before",
                                           "partial",
                                           "after",
                                           "crash-before",
                                           "crash-partial",
                                           "crash-after",
                                           "budget-before",
                                           "budget-partial",
                                           "budget-after",
                                           "budget-crash-before",
                                           "budget-crash-partial",
                                           "budget-crash-after"};
            size_t index;
            int known = 0;
            if (sscanf(line, "receive %31s %4095s", fault, encoded) != 2) return 6;
            for (index = 0; index < sizeof(faults)/sizeof(faults[0]); ++index)
                if (strcmp(fault, faults[index]) == 0) known = 1;
            if (!known) return 7;
            length = 0;
            if (strcmp(encoded, "-") != 0 && !decode_hex(encoded, frame, sizeof(frame), &length)) return 8;
            store.fault = fault;
            memset(output, 0xa5, sizeof(output));
            memset(&result, 0, sizeof(result));
            status = tcsec_receive(&context, frame, length, output, sizeof(output), &result);
            reply(status, &context, &store, &result, output, sizeof(output));
            memset(output, 0, sizeof(output));
        }
    }
    return ferror(stdin) ? 9 : 0;
}
