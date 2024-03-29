#include "sha256_filter.h"

#include <string.h>

#include "interleave.h"

void sha256_pad(uint8_t* block, size_t length, size_t stride) {
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

uint32_t sha256_getfilterone(uint8_t digest[32], size_t length, size_t index, size_t* lifetime) {
    (void) length;
    (void) index;

    if (lifetime != NULL) {
        *lifetime = 1;
    }

    uint32_t* words = (uint32_t*) digest;
    uint32_t H = __builtin_bswap32(words[7]);
    H -= 0x5be0cd19;
    return H;
}
