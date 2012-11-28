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
} SHA1_CTX;

void SHA1Init  (SHA1_CTX* sha1);
void SHA1Update(SHA1_CTX* sha1, const uint8_t* data, uint64_t len);
void SHA1Final (SHA1_CTX* sha1, uint8_t dst[20]); // sets hash in dst and frees sha1

void SHA1(uint8_t dst[20], const uint8_t* src, uint64_t slen);

#endif
