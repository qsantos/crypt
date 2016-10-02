#ifndef MD2_SIMD_H
#define MD2_SIMD_H

#include <stddef.h>
#include <stdint.h>

void md2_pad(uint8_t* block, size_t length, size_t stride);
uint32_t md2_getfilterone(uint8_t digest[16], size_t length, size_t index, size_t* lifetime);

size_t md2_filterone_x86(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);

#endif
