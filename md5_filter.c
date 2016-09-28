#include "md5_filter.h"

uint32_t md5_getfilterone(uint8_t digest[16]) {
    uint32_t* words = (uint32_t*) digest;
    return words[0];  // A after final addition
}
