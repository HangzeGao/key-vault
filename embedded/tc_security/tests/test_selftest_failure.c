#include "tc_security.h"

static tcsec_commit_result_t commit(void *user, const tcsec_commit_t *value) {
    (void)user; (void)value;
    return TCSEC_COMMIT_NEW;
}

static tcsec_status_t load(void *user, tcsec_config_t *config) {
    unsigned int *calls = user;
    (void)config;
    (*calls)++;
    return TCSEC_PERSISTENCE_FAILED;
}

int main(void) {
    tcsec_context_t context = {0};
    tcsec_runtime_status_t status;
    unsigned int calls = 0u;
    const tcsec_callbacks_t callbacks = {
        .load_state = load, .commit_state = commit, .user_context = &calls,
    };
    if (tcsec_init(&context, &callbacks) != TCSEC_SELF_TEST_FAILED ||
        tcsec_init(&context, &callbacks) != TCSEC_SELF_TEST_FAILED ||
        tcsec_get_runtime_status(&context, &status) != TCSEC_SELF_TEST_FAILED ||
        status.self_test != TCSEC_SELF_TEST_LOCKED ||
        tcsec_reset(&context) != TCSEC_SELF_TEST_FAILED || calls != 0u)
        return 1;
    return 0;
}
