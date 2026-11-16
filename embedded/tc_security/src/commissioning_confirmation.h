#ifndef TCSEC_COMMISSIONING_CONFIRMATION_H
#define TCSEC_COMMISSIONING_CONFIRMATION_H

#include <stdint.h>

#define TCSEC_CONFIRM_TRANSCRIPT_LENGTH 192u
#define TCSEC_CONFIRM_PROOF_LENGTH 32u

/* Private maintenance helper. BSP owns verified snapshot loading, fresh
 * challenges and consumption of each exchange. Buffers are disjoint. */
int tcsec_confirm_flight(const uint8_t current[16], const uint8_t recovery[16],
                         const uint8_t transcript[TCSEC_CONFIRM_TRANSCRIPT_LENGTH],
                         uint8_t proof[TCSEC_CONFIRM_PROOF_LENGTH]);

int tcsec_confirm_verify_ground(const uint8_t current[16], const uint8_t recovery[16],
                                const uint8_t transcript[TCSEC_CONFIRM_TRANSCRIPT_LENGTH],
                                const uint8_t proof[TCSEC_CONFIRM_PROOF_LENGTH]);

#endif
