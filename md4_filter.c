#include "md4_filter.h"

uint32_t md4_getfilterone(uint8_t digest[16], size_t length, size_t index) {
    (void) length;
    (void) index;
    uint32_t* words = (uint32_t*) digest;
    return words[0];  // A after final addition
}
