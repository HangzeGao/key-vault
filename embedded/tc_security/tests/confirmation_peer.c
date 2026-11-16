#include "../src/commissioning_confirmation.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    uint8_t roots[32];
    uint8_t transcript[TCSEC_CONFIRM_TRANSCRIPT_LENGTH];
    uint8_t proof[TCSEC_CONFIRM_PROOF_LENGTH];
    int result;
    if (argc != 2 || fread(roots, 1u, sizeof(roots), stdin) != sizeof(roots) ||
        fread(transcript, 1u, sizeof(transcript), stdin) != sizeof(transcript)) return 2;
    if (strcmp(argv[1], "prove") == 0) {
        if (getchar() != EOF || tcsec_confirm_flight(roots, &roots[16], transcript, proof) != 0) return 1;
        return fwrite(proof, 1u, sizeof(proof), stdout) == sizeof(proof) ? 0 : 2;
    }
    if (strcmp(argv[1], "verify") != 0 || fread(proof, 1u, sizeof(proof), stdin) != sizeof(proof) || getchar() != EOF) return 2;
    result = tcsec_confirm_verify_ground(roots, &roots[16], transcript, proof);
    return result == 0 ? 0 : 1;
}
