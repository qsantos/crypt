#ifndef MD4_SIMD_H
#define MD4_SIMD_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "interleave.h"

static inline void md4_pad(uint8_t* block, size_t length, size_t stride) {
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

void md4_oneblock_x86   (uint8_t digest[ 16], const uint8_t block[  64]);
void md4_oneblock_mmx   (uint8_t digest[ 32], const uint8_t block[ 128]);
void md4_oneblock_sse2  (uint8_t digest[ 64], const uint8_t block[ 256]);
void md4_oneblock_avx2  (uint8_t digest[128], const uint8_t block[ 512]);
void md4_oneblock_avx512(uint8_t digest[256], const uint8_t block[1024]);

int md4_test_x86   (const uint8_t digest[ 16], const uint8_t block[  64]);
int md4_test_mmx   (const uint8_t digest[ 32], const uint8_t block[ 128]);
int md4_test_sse2  (const uint8_t digest[ 64], const uint8_t block[ 256]);
int md4_test_avx2  (const uint8_t digest[128], const uint8_t block[ 512]);
int md4_test_avx512(const uint8_t digest[256], const uint8_t block[1024]);

size_t md4_filterone_x86   (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md4_filterone_mmx   (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md4_filterone_sse2  (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md4_filterone_avx2  (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md4_filterone_avx512(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);

#endif
