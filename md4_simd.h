#ifndef MD4_SIMD_H
#define MD4_SIMD_H

#include <stddef.h>
#include <stdint.h>

void md4_pad(uint8_t* block, size_t length, size_t stride);

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

#endif