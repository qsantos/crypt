#ifndef SHA1_SIMD_H
#define SHA1_SIMD_H

#include <stddef.h>
#include <stdint.h>

void sha1_pad(uint8_t* block, size_t length, size_t stride);

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
