#ifndef TEST_STORAGE_QUORUM_MODEL_H
#define TEST_STORAGE_QUORUM_MODEL_H

/* TEST ONLY. Logical model, not a BSP or deployable NVM format. Each lane
 * retains the anchored record while a new record is written elsewhere.
 * The independently protected anchor update is an atomic platform primitive. */
typedef struct {
    tcsec_config_t payload;
    uint32_t checksum;
    uint8_t complete;
} model_record_t;

typedef struct {
    model_record_t lane[3][2];
    unsigned anchor;
    uint32_t anchor_checksum;
    unsigned operations;
    unsigned cut_after;
} quorum_model_t;

static uint32_t model_checksum(const tcsec_config_t *value) {
    const unsigned char *bytes = (const unsigned char *)value;
    uint32_t sum = UINT32_C(2166136261);
    size_t i;
    for (i = 0; i < sizeof(*value); ++i) sum = (sum ^ bytes[i]) * UINT32_C(16777619);
    return sum;
}

static void model_seed(quorum_model_t *store, const tcsec_config_t *value) {
    unsigned lane;
    memset(store, 0, sizeof(*store));
    store->cut_after = UINT32_MAX;
    store->anchor_checksum = model_checksum(value);
    for (lane = 0; lane < 3; ++lane) {
        store->lane[lane][0].payload = *value;
        store->lane[lane][0].checksum = model_checksum(value);
        store->lane[lane][0].complete = 1;
    }
}

static int model_write_step(quorum_model_t *store) {
    return store->operations++ < store->cut_after;
}

static tcsec_status_t model_load(void *user, tcsec_config_t *out) {
    quorum_model_t *store = user;
    unsigned a, b;
    for (a = 0; a < 3; ++a) {
        const model_record_t *one = &store->lane[a][store->anchor];
        if (!one->complete || one->checksum != store->anchor_checksum ||
            one->checksum != model_checksum(&one->payload)) continue;
        for (b = a + 1; b < 3; ++b) {
            const model_record_t *two = &store->lane[b][store->anchor];
            if (two->complete && two->checksum == model_checksum(&two->payload) &&
                memcmp(&one->payload, &two->payload, sizeof(*out)) == 0) {
                *out = one->payload;
                return TCSEC_OK;
            }
        }
    }
    return TCSEC_STORAGE_NO_QUORUM;
}

static tcsec_commit_result_t model_commit(void *user, const tcsec_commit_t *change) {
    quorum_model_t *store = user;
    storage_fixture_t candidate = {0};
    unsigned lane, target = 1u - store->anchor;
    size_t byte;
    if (model_load(store, &candidate.saved) != TCSEC_OK) return TCSEC_COMMIT_REJECTED;
    if (commit_storage(&candidate, change) != TCSEC_COMMIT_NEW) return TCSEC_COMMIT_REJECTED;
    for (lane = 0; lane < 3; ++lane) {
        model_record_t *record = &store->lane[lane][target];
        /* The test starts each transaction with an unused candidate record. */
        for (byte = 0; byte < sizeof(record->payload); ++byte) {
            if (!model_write_step(store)) return TCSEC_COMMIT_PERSISTENCE_FAILED;
            ((unsigned char *)&record->payload)[byte] =
                ((const unsigned char *)&candidate.saved)[byte];
        }
        if (!model_write_step(store)) return TCSEC_COMMIT_PERSISTENCE_FAILED;
        record->checksum = model_checksum(&record->payload);
        if (!model_write_step(store)) return TCSEC_COMMIT_PERSISTENCE_FAILED;
        record->complete = 1;
    }
    if (!model_write_step(store)) return TCSEC_COMMIT_PERSISTENCE_FAILED;
    store->anchor = target;
    store->anchor_checksum = model_checksum(&candidate.saved);
    /* A loss of confirmation is different from a proven rejected write. */
    if (!model_write_step(store)) return TCSEC_COMMIT_UNCERTAIN;
    return TCSEC_COMMIT_NEW;
}

static int test_quorum_powercuts(const char *ordinary_path, const char *recovery_path) {
    vector_t ordinary_vector, recovery_vector;
    unsigned scenario;
    if (!load_vector(ordinary_path, &ordinary_vector) ||
        !load_vector(recovery_path, &recovery_vector)) return 0;
    for (scenario = 0; scenario < 3; ++scenario) {
        tcsec_config_t initial, expected, recovered;
        tcsec_context_t context = {0};
        tcsec_result_t result;
        quorum_model_t store;
        tcsec_callbacks_t callbacks = {
            .load_state = model_load, .commit_state = model_commit, .user_context = &store,
        };
        uint8_t frame[TCSEC_MAX_FRAME_LENGTH], output[TCSEC_MAX_FRAME_LENGTH], key[32];
        size_t frame_length;
        unsigned cut, operations, lane;
        tcsec_status_t event;
        if (scenario == 0) {
            ordinary_config(&initial, &ordinary_vector);
            memcpy(frame, ordinary_vector.protected_frame, ordinary_vector.protected_frame_length);
            frame_length = ordinary_vector.protected_frame_length;
            event = TCSEC_OK;
        } else {
            recovery_config(&initial, &recovery_vector);
            memcpy(frame, recovery_vector.protected_frame, recovery_vector.protected_frame_length);
            frame_length = recovery_vector.protected_frame_length;
            event = TCSEC_ROOT_PREPARED;
            if (scenario == 2) {
                model_seed(&store, &initial);
                if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
                    tcsec_receive(&context, frame, frame_length, output, sizeof(output), &result) !=
                        TCSEC_ROOT_PREPARED || model_load(&store, &initial) != TCSEC_OK) return 0;
                cold_restart(&context);
                if (tcsec_derive_ordinary_key(initial.ordinary.pending_operational_root, 16,
                        initial.ordinary.spacecraft_id, initial.ordinary.pending_suite,
                        (uint16_t)(initial.ordinary.current_spi + 1u), initial.ordinary.current_epoch + 1u,
                        initial.ordinary.pending_root_version, key, sizeof(key)) != 0 ||
                    !build_ordinary_frame(initial.ordinary.pending_suite, key,
                        initial.ordinary.nonce_prefix, (uint16_t)(initial.ordinary.current_spi + 1u),
                        1, next_test_packet, sizeof(next_test_packet), frame, &frame_length)) return 0;
                event = TCSEC_EPOCH_PROMOTED;
            }
        }
        model_seed(&store, &initial);
        if (tcsec_init(&context, &callbacks) != TCSEC_OK ||
            tcsec_receive(&context, frame, frame_length, output, sizeof(output), &result) != event ||
            model_load(&store, &expected) != TCSEC_OK) return 0;
        operations = store.operations;
        /* Cut before each payload byte, checksum, validity marker, anchor and
         * callback confirmation. Reset RAM exactly as a computer restart does. */
        for (cut = 0; cut <= operations; ++cut) {
            tcsec_status_t received;
            model_seed(&store, &initial);
            store.cut_after = cut;
            cold_restart(&context);
            if (tcsec_init(&context, &callbacks) != TCSEC_OK) return 0;
            received = tcsec_receive(&context, frame, frame_length, output, sizeof(output), &result);
            if (received != event && received != TCSEC_PERSISTENCE_FAILED &&
                received != TCSEC_STORAGE_COMMIT_UNCERTAIN) return 0;
            if (received != event && (result.plaintext_length != 0 || output[0] != 0)) return 0;
            cold_restart(&context);
            if (model_load(&store, &recovered) != TCSEC_OK ||
                memcmp(&recovered, store.anchor ? &expected : &initial, sizeof(recovered)) != 0 ||
                tcsec_init(&context, &callbacks) != TCSEC_OK) return 0;
            if (store.anchor != 0 &&
                tcsec_receive(&context, frame, frame_length, output, sizeof(output), &result) !=
                    TCSEC_REPLAY_REJECTED) return 0;
            /* Any one unreadable/corrupt lane still leaves an exact quorum. */
            for (lane = 0; lane < 3; ++lane) {
                store.lane[lane][store.anchor].checksum ^= 1;
                if (model_load(&store, &recovered) != TCSEC_OK) return 0;
                store.lane[lane][store.anchor].checksum ^= 1;
            }
        }
        /* Even an old unanimous payload cannot override the protected anchor. */
        for (lane = 0; lane < 3; ++lane) {
            store.lane[lane][store.anchor].payload = initial;
            store.lane[lane][store.anchor].checksum = model_checksum(&initial);
            store.lane[lane][store.anchor].complete = 1;
        }
        if (model_load(&store, &recovered) != TCSEC_STORAGE_NO_QUORUM) return 0;
    }
    printf("Three-lane model passed: bytewise cuts for replay, prepare and promotion\n");
    return 1;
}

#endif
