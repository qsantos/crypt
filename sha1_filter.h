#ifndef SHA1_SIMD_H
#define SHA1_SIMD_H

#include <stddef.h>
#include <stdint.h>

void sha1_pad(uint8_t* block, size_t length, size_t stride);
uint32_t sha1_getfilterone(uint8_t digest[20], size_t length, size_t index);

size_t sha1_filterone_x86   (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t sha1_filterone_mmx   (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t sha1_filterone_sse2  (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t sha1_filterone_avx2  (size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);
size_t sha1_filterone_avx512(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);

#endif
