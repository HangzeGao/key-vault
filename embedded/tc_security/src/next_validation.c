#include "next_validation.h"

int tcsec_next_plaintext_allowed(uint16_t spacecraft_id,
                                 const uint8_t primary_header[TCSEC_PRIMARY_HEADER_LENGTH],
                                 const uint8_t *plaintext, size_t plaintext_length) {
    const size_t packet_header_length = 6u;
    uint16_t frame_spacecraft;
    uint16_t apid;
    uint8_t vcid;
    size_t body_length;

    if (primary_header == NULL || plaintext == NULL ||
        plaintext_length <= packet_header_length ||
        plaintext_length > TCSEC_MAX_FRAME_LENGTH - TCSEC_PRIMARY_HEADER_LENGTH -
                               TCSEC_SECURITY_HEADER_LENGTH - TCSEC_FECF_LENGTH)
        return 0;

    /* TC frame version 0, bypass, data frame, reserved bits clear. The caller
     * has already checked the complete frame's declared length and FECF. */
    if ((primary_header[0] & 0xfcu) != 0x20u) return 0;
    frame_spacecraft = (uint16_t)(((uint16_t)(primary_header[0] & 0x03u) << 8) |
                                  primary_header[1]);
    if (frame_spacecraft != spacecraft_id) return 0;
    vcid = (uint8_t)(primary_header[2] >> 2);

    /* Exactly one unsegmented version-0 TC Space Packet, no secondary header. */
    if ((plaintext[0] & 0xf8u) != 0x10u || (plaintext[2] & 0xc0u) != 0xc0u)
        return 0;
    apid = (uint16_t)(((uint16_t)(plaintext[0] & 0x07u) << 8) | plaintext[1]);
    if (apid == 0x07ffu) return 0;
    body_length = (size_t)(((uint16_t)plaintext[4] << 8) | plaintext[5]) + 1u;
    if (body_length != plaintext_length - packet_header_length) return 0;
    return tcsec_mission_next_command_allowed(vcid, apid, plaintext + packet_header_length,
                                              body_length) == 1;
}
