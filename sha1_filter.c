#include "sha1_filter.h"

uint32_t sha1_getfilterone(uint8_t digest[20]) {
    uint32_t* words = (uint32_t*) digest;
    return words[0];  // A after final addition
}
