#include "sha1_filter.h"

#include <string.h>

#include "interleave.h"

void sha1_pad(uint8_t* block, size_t length, size_t stride) {
    memset(block, 0, 64 * stride);
    for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
        size_t offset;

        // data termination
        offset = interleaved_offset(length, stride, interleaf);
        block[offset] = 0x80;

        // length in bits
        size_t bits = length * 8;
        for (size_t i = 8; i --> 0; ) {
            offset = interleaved_offset(56 + i, stride, interleaf);
            block[offset] = (uint8_t) bits;
            bits >>= 8;
        }
    }
}


uint32_t sha1_getfilterone(uint8_t digest[20], size_t length, size_t index) {
    (void) length;
    (void) index;
    uint32_t* words = (uint32_t*) digest;
    uint32_t A = __builtin_bswap32(words[0]);
    return A;
}
