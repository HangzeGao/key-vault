#ifndef TCSEC_NEXT_VALIDATION_H
#define TCSEC_NEXT_VALIDATION_H

#include "parameters.h"

/* Private compile-time seam. A flight build must link the mission's fixed
 * policy; there is no default policy or runtime callback. Return exactly 1
 * only for an allowed VCID/APID/command and a complete, canonical body. */
int tcsec_mission_next_command_allowed(uint8_t vcid, uint16_t apid,
                                       const uint8_t *body, size_t body_length);

int tcsec_next_plaintext_allowed(uint16_t spacecraft_id,
                                 const uint8_t primary_header[TCSEC_PRIMARY_HEADER_LENGTH],
                                 const uint8_t *plaintext, size_t plaintext_length);

#endif
