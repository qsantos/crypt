#ifndef SHA256_H
#define SHA256_H

// SHA-2: SHA-224/SHA-256
// SHA256 provides a 32 byte hash
// SHA224 provides a 28 byte hash
#include <stdint.h>

typedef struct
{
	uint8_t bufLen;
	uint8_t buffer[64];
	uint32_t H[8];
	uint64_t len;
} SHA256ctx;
SHA256ctx* SHA256_new();
void SHA256_push(SHA256ctx* sha256, uint32_t len, const uint8_t* data);
void SHA256_hash(SHA256ctx* sha256, uint8_t dst[32]); // sets hash in dst and frees sha256
void SHA256(uint32_t len, const uint8_t* src, uint8_t dst[32]);

typedef SHA256ctx SHA224ctx;
SHA224ctx* SHA224_new();
void SHA224_push(SHA224ctx* sha224, uint32_t len, const uint8_t* data);
void SHA224_hash(SHA224ctx* sha224, uint8_t dst[28]); // sets hash in dst and frees sha224
void SHA224(uint32_t len, const uint8_t* src, uint8_t dst[28]);

#endif
