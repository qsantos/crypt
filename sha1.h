#ifndef SHA1_H
#define SHA1_H

// SHA1 provides a 20 byte hash
#include <stdint.h>

typedef struct
{
	uint8_t bufLen;
	uint8_t buffer[64];
	uint32_t H[5];
	uint64_t len;
} SHA1ctx;

void SHA1Init  (SHA1ctx* sha1);
void SHA1Update(SHA1ctx* sha1, uint64_t len, const uint8_t* data);
void SHA1Final (SHA1ctx* sha1, uint8_t dst[20]); // sets hash in dst and frees sha1

// one-call digest (NOT THREAD-SAFE)
void SHA1(uint64_t slen, const uint8_t* src, uint8_t dst[20]);

#endif
