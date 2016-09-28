#ifndef MD4_SIMD_H
#define MD4_SIMD_H

#include <stddef.h>
#include <stdint.h>

void md4_pad(uint8_t* block, size_t length, size_t stride);
uint32_t md4_getfilterone(uint8_t digest[16], size_t length, size_t index);

size_t md4_filterone_x86   (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md4_filterone_mmx   (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md4_filterone_sse2  (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md4_filterone_avx2  (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t md4_filterone_avx512(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);

#endif
