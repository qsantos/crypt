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
} SHA512_CTX;

void SHA512Init  (SHA512_CTX* sha512);
void SHA512Update(SHA512_CTX* sha512, const uint8_t* data, uint64_t len);
void SHA512Final (SHA512_CTX* sha512, uint8_t dst[64]); // sets hash in dst and frees sha512

void SHA512(uint64_t slen, const uint8_t* src, uint8_t dst[64]);



typedef SHA512_CTX SHA384_CTX;

void SHA384Init  (SHA384_CTX* sha384);
void SHA384Update(SHA384_CTX* sha384, const uint8_t* data, uint64_t len);
void SHA384Final (SHA384_CTX* sha384, uint8_t dst[48]); // sets hash in dst and frees sha384

void SHA384(uint64_t slen, const uint8_t* src, uint8_t dst[48]);

#endif
