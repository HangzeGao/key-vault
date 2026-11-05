#include "next_validation.h"

#if !defined(TCSEC_TEST_NEXT_POLICY)
#error "This synthetic mission policy is for tests only"
#endif

int tcsec_mission_next_command_allowed(uint8_t vcid, uint16_t apid,
                                       const uint8_t *body, size_t body_length) {
    size_t index;
    /* TEST ONLY: two ordinary command codes sharing one canonical body. */
    if (vcid != 0u || apid != 0x42u || body_length != 10u) return 0;
    if ((body[0] != 1u && body[0] != 2u) || body[1] > 3u) return 0;
    for (index = 2u; index < body_length; ++index) {
        if (body[index] != 0u) return 0;
    }
    return 1;
}
