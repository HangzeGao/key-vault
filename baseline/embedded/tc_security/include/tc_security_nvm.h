#ifndef TC_SECURITY_NVM_H
#define TC_SECURITY_NVM_H

#include "tc_security.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TCSEC_NVM_IMAGE_LENGTH 175u

typedef struct {
    uint32_t generation;
    tcsec_config_t config;
} tcsec_nvm_image_t;

typedef struct {
    uint8_t required;
    uint8_t target_slot;
    uint32_t generation;
    uint8_t encoded[TCSEC_NVM_IMAGE_LENGTH];
} tcsec_nvm_repair_plan_t;

/* Deterministic, endian-stable serialization for one physical NVM slot. */
tcsec_status_t tcsec_nvm_encode(const tcsec_nvm_image_t *image,
                                uint8_t *output,
                                size_t output_capacity,
                                size_t *output_length);

/* Decoding validates format, CRC32C/inverse, generation floor, and the complete
 * tcsec configuration before returning any root material to the caller. */
tcsec_status_t tcsec_nvm_decode(const uint8_t *encoded,
                                size_t encoded_length,
                                uint32_t minimum_generation,
                                tcsec_nvm_image_t *image);

/* Selects the highest valid generation from two independently written slots.
 * Equal-generation slots must be byte-identical. selected_slot is 0 or 1. */
tcsec_status_t tcsec_nvm_select_latest(const uint8_t *slot0,
                                       size_t slot0_length,
                                       const uint8_t *slot1,
                                       size_t slot1_length,
                                       uint32_t minimum_generation,
                                       tcsec_nvm_image_t *image,
                                       uint8_t *selected_slot);

/* Selects the authoritative slot and, when exactly one slot is invalid,
 * prepares a next-generation replacement for the invalid slot. The BSP owns
 * erase/write/read-back and must advance its trusted generation floor only
 * after verifying tcsec_nvm_decode on the written bytes. */
tcsec_status_t tcsec_nvm_plan_repair(const uint8_t *slot0,
                                     size_t slot0_length,
                                     const uint8_t *slot1,
                                     size_t slot1_length,
                                     uint32_t minimum_generation,
                                     tcsec_nvm_image_t *selected_image,
                                     uint8_t *selected_slot,
                                     tcsec_nvm_repair_plan_t *repair);

#ifdef __cplusplus
}
#endif

#endif
