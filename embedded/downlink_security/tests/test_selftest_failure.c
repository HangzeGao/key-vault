#include "downlink_security.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t key[32] = {0}, input[880] = {0}, output[882];
    size_t iteration, index;
    for (iteration = 0u; iteration < 3u; ++iteration) {
        memset(output, 0xa5, sizeof(output));
        if (dlsec_encrypt_data(key, sizeof(key), input, sizeof(input), output + 1u, 881u) != DLSEC_SELF_TEST_FAILED) return 1;
        for (index = 1u; index <= 880u; ++index) if (output[index] != 0u) return 1;
        if (output[0] != 0xa5u || output[881] != 0xa5u) return 1;
        memset(input, 0xa5, sizeof(input));
        if (dlsec_encrypt_data(key, sizeof(key), input, sizeof(input), input, sizeof(input)) != DLSEC_SELF_TEST_FAILED) return 1;
        for (index = 0u; index < sizeof(input); ++index) if (input[index] != 0u) return 1;
    }
    puts("AES downlink KAT failure closed and output cleared");
    return 0;
}
