#include "sha1_filter.h"

uint32_t sha1_getfilterone(uint8_t digest[20]) {
    uint32_t* words = (uint32_t*) digest;
    uint32_t A = __builtin_bswap32(words[0]);
    return A;
}
