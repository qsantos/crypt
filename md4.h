#ifndef MD4_H
#define MD4_H

// MD3 provides a 16 byte hash
#include <stdint.h>

typedef struct
{
	uint8_t bufLen;
	uint8_t buffer[64];
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint64_t len;
} MD4_CTX;

void MD4Init  (MD4_CTX* md4);
void MD4Update(MD4_CTX* md4, uint64_t len, const uint8_t* data);
void MD4Final (MD4_CTX* md4, uint8_t dst[16]); // sets hash in dst and frees md4

void MD4(uint64_t slen, const uint8_t* src, uint8_t dst[16]);

#endif
