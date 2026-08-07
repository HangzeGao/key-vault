#ifndef TC_SECURITY_KDF_H
#define TC_SECURITY_KDF_H

#include "tc_security.h"

#include <stddef.h>
#include <stdint.h>

int tcsec_derive_ordinary_key(const uint8_t *root, size_t root_length,
                              uint16_t spacecraft_id, tcsec_suite_t ordinary_suite,
                              uint16_t spi, uint32_t security_epoch, uint32_t key_version,
                              uint8_t *output, size_t output_capacity);

int tcsec_derive_recovery_key(const uint8_t *root, size_t root_length,
                              uint16_t spacecraft_id, tcsec_suite_t recovery_suite,
                              uint16_t spi, uint32_t recovery_key_version,
                              uint8_t *output, size_t output_capacity);

#endif
