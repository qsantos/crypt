#ifndef SIMD_H
#define SIMD_H

#include <stddef.h>
#include <stdint.h>

static inline size_t interleaved_offset(size_t uninterleaved_offset, size_t stride, size_t interleaf) {
    /*
    AAAA BBBB CCCC AAAA BBBB CCCC AAAA BBBB CCCC
    ^^^^ ^^^^ ^^^^ ^^^^ ^^^^ ^^^^ ^^^^ ^^^^ ^^^^
    granularity = 4 (bytes)
    stride = 3


    AAAA BBBB CCCC AAAA BBBB CCCC AAAA BBBB CCCC
                        ^^^^
    interleaf = 1 (B)
    block_index = 1 (second block in B)
    interleaved_block = 4 (5-th block in interleaved sequence)


    AAAA BBBB CCCC AAAA BBBB CCCC AAAA BBBB CCCC
                          ^
    in_block_offset = 2 (3-rd byte in block)
    uninterleaved_offset = 6 (7-th B)
    interleaved_offset = 18 (19-th byte)
    */
    size_t granularity = 4;
    size_t block_index = uninterleaved_offset / granularity;
    size_t in_block_offset = uninterleaved_offset % granularity;
    size_t interleaved_block = block_index * stride + interleaf;
    return interleaved_block * granularity + in_block_offset;
}

static inline void interleave(uint8_t* dst, const uint8_t* src, size_t length, size_t stride, size_t interleaf) {
    for (size_t i = 0; i < length; i++) {
        size_t offset = interleaved_offset(i, stride, interleaf);
        dst[offset] = src[i];
    }
}

static inline void uninterleave(uint8_t* dst, const uint8_t* src, size_t length, size_t stride, size_t interleaf) {
    for (size_t i = 0; i < length; i++) {
        size_t offset = interleaved_offset(i, stride, interleaf);
        dst[i] = src[offset];
    }
}

#endif
