#ifndef MD5_SIMD_H
#define MD5_SIMD_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "interleave.h"

static inline void md5_pad(uint8_t* block, size_t length, size_t stride) {
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

size_t md5_filterone_x86   (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md5_filterone_mmx   (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md5_filterone_sse2  (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md5_filterone_avx2  (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md5_filterone_avx512(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);

#endif
