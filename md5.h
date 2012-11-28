#ifndef MD5_H
#define MD5_H

// MD5 provides a 16 byte hash
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
} MD5ctx;

void MD5Init  (MD5ctx* md5);
void MD5Update(MD5ctx* md5, uint64_t len, const uint8_t* data);
void MD5Final (MD5ctx* md5, uint8_t dst[16]); // sets hash in dst and frees md5

void MD5(uint64_t slen, const uint8_t* src, uint8_t dst[16]);

#endif
