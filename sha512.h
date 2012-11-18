#ifndef SHA512_h
#define SHA512_h

// SHA-2: SHA-384/SHA-512
// SHA512 provides a 64 byte hash
// SHA384 provides a 48 byte hash
#include <stdint.h>

typedef struct
{
	uint8_t bufLen;
	uint8_t buffer[128];
	uint64_t H[8];
	uint64_t len[2];
} SHA512ctx;
SHA512ctx* SHA512_new();
void SHA512_push(SHA512ctx* sha512, uint64_t len, const uint8_t* data);
void SHA512_hash(SHA512ctx* sha512, uint8_t dst[64]); // sets hash in dst and frees sha512
void SHA512(uint64_t len, const uint8_t* src, uint8_t dst[64]);

typedef SHA512ctx SHA384ctx;
SHA384ctx* SHA384_new();
void SHA384_push(SHA384ctx* sha384, uint64_t len, const uint8_t* data);
void SHA384_hash(SHA384ctx* sha384, uint8_t dst[48]); // sets hash in dst and frees sha384
void SHA384(uint64_t len, const uint8_t* src, uint8_t dst[48]);

#endif
