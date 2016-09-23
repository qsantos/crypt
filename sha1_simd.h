#ifndef SHA1_SIMD_H
#define SHA1_SIMD_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "interleave.h"

static inline void sha1_pad(uint8_t* block, size_t length, size_t stride) {
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

void sha1_oneblock_x86   (uint8_t digest[ 20], const uint8_t block[  64]);
void sha1_oneblock_mmx   (uint8_t digest[ 40], const uint8_t block[ 128]);
void sha1_oneblock_sse2  (uint8_t digest[ 80], const uint8_t block[ 256]);
void sha1_oneblock_avx2  (uint8_t digest[160], const uint8_t block[ 512]);
void sha1_oneblock_avx512(uint8_t digest[320], const uint8_t block[1024]);

int sha1_test_x86   (const uint8_t digest[ 20], const uint8_t block[  64]);
int sha1_test_mmx   (const uint8_t digest[ 40], const uint8_t block[ 128]);
int sha1_test_sse2  (const uint8_t digest[ 80], const uint8_t block[ 256]);
int sha1_test_avx2  (const uint8_t digest[160], const uint8_t block[ 512]);
int sha1_test_avx512(const uint8_t digest[320], const uint8_t block[1024]);

#endif
