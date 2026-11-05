/* Host integration harness with public TEST ONLY roots. Not a flight driver. */
#define _POSIX_C_SOURCE 200809L
#define main ordinary_test_main
#include "test_tc_security.c"
#undef main
#include <fcntl.h>
#include <unistd.h>

typedef struct {
    tcsec_config_t config;
    uint32_t checksum;
} disk_record_t;
typedef struct {
    const char *path;
    const char *fault;
} disk_store_t;

static tcsec_status_t disk_load(void *user, tcsec_config_t *out) {
    const disk_store_t *store = user;
    disk_record_t record;
    FILE *file = fopen(store->path,"rb");
    int valid;
    if (file == NULL) return TCSEC_STATE_INTEGRITY_FAILED;
    valid = fread(&record,sizeof(record),1,file) == 1 && fgetc(file) == EOF &&
            record.checksum == model_checksum(&record.config);
    fclose(file);
    if (valid) *out = record.config;
    memset(&record,0,sizeof(record));
    return valid ? TCSEC_OK : TCSEC_STATE_INTEGRITY_FAILED;
}

static tcsec_commit_result_t disk_commit(void *user, const tcsec_commit_t *change) {
    disk_store_t *store = user;
    storage_fixture_t candidate = {0};
    disk_record_t record = {0};
    char temporary[4096], directory[4096], *slash;
    FILE *file;
    int written, directory_fd;
    if (strcmp(store->fault,"before") == 0) return TCSEC_COMMIT_PERSISTENCE_FAILED;
    if (disk_load(store,&candidate.saved) != TCSEC_OK ||
        commit_storage(&candidate,change) != TCSEC_COMMIT_NEW) return TCSEC_COMMIT_REJECTED;
    record.config = candidate.saved;
    record.checksum = model_checksum(&record.config);
    if (snprintf(temporary,sizeof(temporary),"%s.candidate",store->path) >= (int)sizeof(temporary) ||
        snprintf(directory,sizeof(directory),"%s",store->path) >= (int)sizeof(directory)) return TCSEC_COMMIT_REJECTED;
    file = fopen(temporary,"wb");
    if (file == NULL) return TCSEC_COMMIT_PERSISTENCE_FAILED;
    written = fwrite(&record,sizeof(record),1,file) == 1;
    if (fflush(file) != 0 || fsync(fileno(file)) != 0) written = 0;
    if (fclose(file) != 0) written = 0;
    memset(&record,0,sizeof(record));
    memset(&candidate,0,sizeof(candidate));
    if (!written || rename(temporary,store->path) != 0) return TCSEC_COMMIT_PERSISTENCE_FAILED;
    slash = strrchr(directory,'/');
    if (slash == NULL) return TCSEC_COMMIT_UNCERTAIN;
    *slash = '\0';
    directory_fd = open(directory,O_RDONLY);
    if (directory_fd < 0) return TCSEC_COMMIT_UNCERTAIN;
    written = fsync(directory_fd) == 0;
    close(directory_fd);
    return written && strcmp(store->fault,"after") != 0 ? TCSEC_COMMIT_NEW : TCSEC_COMMIT_UNCERTAIN;
}

int main(int argc, char **argv) {
    vector_t vector;
    disk_store_t store;
    tcsec_context_t context = {0};
    tcsec_callbacks_t callbacks;
    tcsec_result_t result = {0};
    tcsec_status_t status;
    uint8_t frame[TCSEC_MAX_FRAME_LENGTH], output[TCSEC_MAX_FRAME_LENGTH] = {0};
    size_t length, index;
    int cleared = 1;
    if ((argc != 4 && argc != 6) || !load_vector(argv[1],&vector)) return 2;
    if (argc == 4 && strcmp(argv[3],"commission") == 0) {
        disk_record_t record = {0};
        FILE *file = fopen(argv[2],"wbx");
        int written;
        if (file == NULL) return 3;
        ordinary_config(&record.config,&vector);
        record.checksum = model_checksum(&record.config);
        written = fwrite(&record,sizeof(record),1,file) == 1;
        if (fflush(file) != 0 || fsync(fileno(file)) != 0) written = 0;
        if (fclose(file) != 0) written = 0;
        memset(&record,0,sizeof(record));
        return written ? 0 : 4;
    }
    if (argc != 6 || strcmp(argv[3],"receive") != 0 ||
        !decode_hex(argv[4],frame,sizeof(frame),&length)) return 5;
    store.path = argv[2]; store.fault = argv[5];
    memset(&callbacks,0,sizeof(callbacks));
    callbacks.load_state = disk_load; callbacks.commit_state = disk_commit;
    callbacks.user_context = &store;
    status = tcsec_init(&context,&callbacks);
    if (status == TCSEC_OK)
        status = tcsec_receive(&context,frame,length,output,sizeof(output),&result);
    for (index = 0; index < sizeof(output); ++index) if (output[index] != 0) cleared = 0;
    printf("{\"status\":\"%s\",\"length\":%lu,\"matches\":%s,\"cleared\":%s}\n",
        tcsec_status_string(status),(unsigned long)result.plaintext_length,
        result.plaintext_length == vector.plaintext_length &&
            memcmp(output,vector.plaintext,vector.plaintext_length) == 0 ? "true" : "false",
        cleared ? "true" : "false");
    return 0;
}
