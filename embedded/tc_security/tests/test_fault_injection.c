/* Host-only link-time fault injection. Production objects have no test hooks. */
#define main ordinary_test_main
#include "test_tc_security.c"
#undef main
#include "selftest.h"

static int fail_selftest;
static int fail_derive;
static int corrupt_ordinary_repeat;
static int corrupt_recovery_repeat;
static int fail_hctr;
static unsigned fail_gcm_call;
static unsigned derive_calls, recovery_calls, gcm_calls;

int __real_tcsec_crypto_self_test(tcsec_crypto_backend_t *backend);
int __wrap_tcsec_crypto_self_test(tcsec_crypto_backend_t *backend) {
    int result, saved_derive = fail_derive, saved_hctr = fail_hctr;
    int saved_ordinary = corrupt_ordinary_repeat, saved_recovery = corrupt_recovery_repeat;
    unsigned saved_gcm = fail_gcm_call;
    if (fail_selftest) return -1;
    fail_derive = fail_hctr = corrupt_ordinary_repeat = corrupt_recovery_repeat = 0;
    fail_gcm_call = 0;
    result = __real_tcsec_crypto_self_test(backend);
    fail_derive = saved_derive; fail_hctr = saved_hctr;
    corrupt_ordinary_repeat = saved_ordinary; corrupt_recovery_repeat = saved_recovery;
    fail_gcm_call = saved_gcm;
    derive_calls = recovery_calls = gcm_calls = 0;
    return result;
}

int __real_tcsec_derive_ordinary_key(const uint8_t *, size_t, uint16_t, tcsec_suite_t,
                                    uint16_t, uint32_t, uint32_t, uint8_t *, size_t);
int __wrap_tcsec_derive_ordinary_key(const uint8_t *root, size_t length, uint16_t scid,
                                    tcsec_suite_t suite, uint16_t spi, uint32_t epoch,
                                    uint32_t version, uint8_t *out, size_t capacity) {
    int result;
    if (fail_derive) return -1;
    result = __real_tcsec_derive_ordinary_key(root,length,scid,suite,spi,epoch,version,out,capacity);
    if (result == 0 && corrupt_ordinary_repeat && ++derive_calls == 2) out[0] ^= 1;
    return result;
}

int __real_tcsec_derive_recovery_key(const uint8_t *, size_t, uint16_t, tcsec_suite_t,
                                    uint16_t, uint32_t, uint8_t *, size_t);
int __wrap_tcsec_derive_recovery_key(const uint8_t *root, size_t length, uint16_t scid,
                                    tcsec_suite_t suite, uint16_t spi, uint32_t version,
                                    uint8_t *out, size_t capacity) {
    int result = __real_tcsec_derive_recovery_key(root,length,scid,suite,spi,version,out,capacity);
    if (result == 0 && corrupt_recovery_repeat && ++recovery_calls == 2) out[0] ^= 1;
    return result;
}

int __real_tcsec_sm4_hctr_decrypt(const uint8_t *, const uint8_t *, const uint8_t *, uint8_t *, size_t);
int __wrap_tcsec_sm4_hctr_decrypt(const uint8_t *key, const uint8_t *tweak,
                                 const uint8_t *in, uint8_t *out, size_t length) {
    return fail_hctr ? -1 : __real_tcsec_sm4_hctr_decrypt(key,tweak,in,out,length);
}

int __real_tcsec_gcm_open(tcsec_suite_t, const uint8_t *, const uint8_t *, const uint8_t *,
                         size_t, const uint8_t *, size_t, const uint8_t *, uint8_t *);
int __wrap_tcsec_gcm_open(tcsec_suite_t suite, const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_length, const uint8_t *in,
                         size_t length, const uint8_t *tag, uint8_t *out) {
    if (++gcm_calls == fail_gcm_call) return -1;
    return __real_tcsec_gcm_open(suite,key,nonce,aad,aad_length,in,length,tag,out);
}

int main(int argc, char **argv) {
    vector_t ordinary, recovery;
    tcsec_context_t context = {0};
    callbacks_t fixture = {.result=TCSEC_COMMIT_NEW};
    tcsec_runtime_status_t runtime;
    tcsec_result_t result;
    tcsec_config_t config;
    uint8_t output[TCSEC_MAX_FRAME_LENGTH], frame[TCSEC_MAX_FRAME_LENGTH], key[32];
    size_t frame_length;
    const tcsec_callbacks_t callbacks = {.load_state=load_snapshot, .commit_state=commit_state,
                                         .user_context=&fixture};
    if (argc != 3 || !load_vector(argv[1], &ordinary) || !load_vector(argv[2], &recovery)) return 2;
    ordinary_config(&fixture.snapshot, &ordinary);
    fail_selftest = 1;
    if (tcsec_init(&context,&callbacks) != TCSEC_SELF_TEST_FAILED ||
        tcsec_reset(&context) != TCSEC_SELF_TEST_FAILED ||
        tcsec_get_runtime_status(&context,&runtime) != TCSEC_SELF_TEST_FAILED ||
        runtime.self_test != TCSEC_SELF_TEST_LOCKED ||
        tcsec_receive(&context,ordinary.protected_frame,ordinary.protected_frame_length,
                      output,sizeof(output),&result) != TCSEC_SELF_TEST_FAILED) return 3;
    cold_restart(&context);
    fail_selftest = 0;
    if (tcsec_init(&context,&callbacks) != TCSEC_OK) return 4;
    fail_selftest = 1;
    if (tcsec_reset(&context) != TCSEC_SELF_TEST_FAILED ||
        tcsec_get_runtime_status(&context,&runtime) != TCSEC_SELF_TEST_FAILED ||
        runtime.self_test != TCSEC_SELF_TEST_LOCKED) return 5;
    fail_selftest = 0;
    cold_restart(&context);
    fail_derive = 1;
    if (tcsec_init(&context,&callbacks) != TCSEC_KEY_DERIVATION_FAILED) return 6;
    fail_derive = 0;
    corrupt_ordinary_repeat = 1;
    if (tcsec_init(&context,&callbacks) != TCSEC_KEY_DERIVATION_FAILED) return 7;
    corrupt_ordinary_repeat = 0;
    corrupt_recovery_repeat = 1;
    if (tcsec_init(&context,&callbacks) != TCSEC_KEY_DERIVATION_FAILED) return 8;
    corrupt_recovery_repeat = 0;
    if (tcsec_init(&context,&callbacks) != TCSEC_OK) return 9;
    fail_hctr = 1;
    if (tcsec_receive(&context,ordinary.protected_frame,ordinary.protected_frame_length,
                     output,sizeof(output),&result) != TCSEC_INVALID_CONFIGURATION ||
        result.plaintext_length != 0 || output[0] != 0 || fixture.calls != 0) return 10;
    fail_hctr = 0;
    if (tcsec_derive_ordinary_key(ordinary.root,ordinary.root_length,ordinary.spacecraft_id,
            ordinary.suite,(uint16_t)(ordinary.spi+1u),ordinary.security_epoch+1u,
            ordinary.root_version,key,sizeof(key)) != 0 ||
        !build_ordinary_frame(ordinary.suite,key,ordinary.prefix,(uint16_t)(ordinary.spi+1u),
            1,next_test_packet,sizeof(next_test_packet),frame,&frame_length)) return 11;
    fail_derive = 1;
    if (tcsec_receive(&context,frame,frame_length,output,sizeof(output),&result) !=
            TCSEC_KEY_DERIVATION_FAILED || output[0] != 0 || fixture.calls != 0) return 12;
    fail_derive = 0;
    cold_restart(&context);
    recovery_config(&config,&recovery);
    fixture.snapshot = config;
    if (tcsec_init(&context,&callbacks) != TCSEC_OK) return 13;
    fail_gcm_call = 2;
    if (tcsec_receive(&context,recovery.protected_frame,recovery.protected_frame_length,
            output,sizeof(output),&result) != TCSEC_STATE_INTEGRITY_FAILED ||
        output[0] != 0 || fixture.calls != 0) return 14;
    fail_gcm_call = 0;
    if (tcsec_reset(&context) != TCSEC_OK) return 15;
    fail_derive = 1;
    if (tcsec_receive(&context,recovery.protected_frame,recovery.protected_frame_length,
            output,sizeof(output),&result) != TCSEC_KEY_DERIVATION_FAILED ||
        output[0] != 0 || fixture.calls != 0) return 16;
    puts("Link-time faults passed: self-test, repeated KDF, HCTR, GCM and candidate keys");
    return 0;
}
