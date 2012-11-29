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
} SHA256_CTX;

void SHA256Init  (SHA256_CTX* sha256);
void SHA256Update(SHA256_CTX* sha256, const uint8_t* data, uint64_t len);
void SHA256Final (SHA256_CTX* sha256, uint8_t dst[32]);

void SHA256(uint8_t dst[32], const uint8_t* src, uint64_t slen);



typedef SHA256_CTX SHA224_CTX;

void SHA224Init  (SHA224_CTX* sha224);
void SHA224Update(SHA224_CTX* sha224, const uint8_t* data, uint64_t len);
void SHA224Final (SHA224_CTX* sha224, uint8_t dst[28]);

void SHA224(uint8_t dst[28], const uint8_t* src, uint64_t slen);

#endif
