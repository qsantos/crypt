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

void SHA512Init  (SHA512ctx* sha512);
void SHA512Update(SHA512ctx* sha512, uint64_t len, const uint8_t* data);
void SHA512Final (SHA512ctx* sha512, uint8_t dst[64]); // sets hash in dst and frees sha512

// one-call digest (NOT THREAD-SAFE)
void SHA512(uint64_t slen, const uint8_t* src, uint8_t dst[64]);



typedef SHA512ctx SHA384ctx;

void SHA384Init  (SHA384ctx* sha384);
void SHA384Update(SHA384ctx* sha384, uint64_t len, const uint8_t* data);
void SHA384Final (SHA384ctx* sha384, uint8_t dst[48]); // sets hash in dst and frees sha384

// one-call digest (NOT THREAD-SAFE)
void SHA384(uint64_t slen, const uint8_t* src, uint8_t dst[48]);

#endif
