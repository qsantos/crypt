#include "md5_filter.h"

#include <string.h>

#include "interleave.h"

void md5_pad(uint8_t* block, size_t length, size_t stride) {
    memset(block, 0, 64 * stride);
    for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
        size_t offset;

        // data termination
        offset = interleaved_offset(length, stride, interleaf);
        block[offset] = 0x80;

        // length in bits
        offset = interleaved_offset(56, stride, interleaf);
        *(uint32_t*) (block + offset) = (uint32_t) (length * 8);
    }
}

uint32_t md5_getfilterone(uint8_t digest[16], size_t length, size_t index) {
    (void) length;
    (void) index;
    uint32_t* words = (uint32_t*) digest;
    return words[0];  // A after final addition
}
