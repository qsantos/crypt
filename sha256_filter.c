#include "sha256_filter.h"

uint32_t sha256_getfilterone(uint8_t digest[32]) {
    uint32_t* words = (uint32_t*) digest;
    uint32_t A = __builtin_bswap32(words[0]);
    return A;
}
