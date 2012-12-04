// Reference:
// Federal Information Processing Standards Publication
// (FIPS PUB) 180-2, Secure Hash Standard, 1 August 2002.
#include "sha256.h"

#include <string.h>

static const uint8_t* padding = (uint8_t*)
	"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
;

static const uint32_t K[] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const SHA256_CTX initctx256 =
{
	0, 0, {0},
	{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
};

void SHA256Init(SHA256_CTX* sha256)
{
	memcpy(sha256, &initctx256, sizeof(SHA256_CTX));
}

#define  Ch(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define Maj(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define ROTL(x,n) (((x) << n) | ((x) >> (32-n)))
#define ROTR(x,n) (((x) >> n) | ((x) << (32-n)))
#define  SHR(x,n) ((x) >> n)
#define   Sum0(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define   Sum1(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define Sigma0(x) (ROTR(x, 7) ^ ROTR(x,18) ^ SHR (x, 3))
#define Sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR (x,10))
void SHA256Block(SHA256_CTX* sha256, const uint8_t block[64])
{
	uint32_t W[64];
	for (uint8_t t = 0; t < 16; t++)
		W[t] = (block[t*4] << 24) | (block[t*4+1] << 16) | (block[t*4+2] << 8) | (block[t*4+3] << 0);

	for (uint8_t t = 16; t < 64; t++)
		W[t] = Sigma1(W[t-2]) + W[t-7] + Sigma0(W[t-15]) + W[t-16];

	uint32_t a = sha256->H[0];
	uint32_t b = sha256->H[1];
	uint32_t c = sha256->H[2];
	uint32_t d = sha256->H[3];
	uint32_t e = sha256->H[4];
	uint32_t f = sha256->H[5];
	uint32_t g = sha256->H[6];
	uint32_t h = sha256->H[7];

	uint32_t T1;
	uint32_t T2;
	for (uint8_t t = 0; t < 64; t++)
	{
		T1 = h + Sum1(e) + Ch (e,f,g) + K[t] + W[t];
		T2 =     Sum0(a) + Maj(a,b,c);
		h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
	}
	T1 = 0;
	T2 = 0;

	sha256->H[0] += a;
	sha256->H[1] += b;
	sha256->H[2] += c;
	sha256->H[3] += d;
	sha256->H[4] += e;
	sha256->H[5] += f;
	sha256->H[6] += g;
	sha256->H[7] += h;

	// TODO : true cleaning
}

void SHA256Update(SHA256_CTX* sha256, const uint8_t* data, uint64_t len)
{
	uint32_t i = 0;
	uint8_t availBuf = 64 - sha256->bufLen;
	if (len >= availBuf)
	{
		memcpy(sha256->buffer + sha256->bufLen, data, availBuf);
		SHA256Block(sha256, sha256->buffer);
		i = availBuf;
		sha256->bufLen = 0;

		while (i + 63 < len)
		{
			SHA256Block(sha256, data + i);
			i+= 64;
		}
	}
	memcpy(sha256->buffer + sha256->bufLen, data + i, len - i);
	sha256->bufLen += len - i;
	sha256->len += len;

	// TODO : true cleaning
}

static void u32to8(uint32_t v, uint8_t* dst)
{
	dst[0] = (v >> 24) & 0xFF;
	dst[1] = (v >> 16) & 0xFF;
	dst[2] = (v >>  8) & 0xFF;
	dst[3] = (v >>  0) & 0xFF;

	// TODO : true cleaning
}

void SHA256Final(SHA256_CTX* sha256, uint8_t dst[32])
{
	uint64_t len = sha256->len << 3;
	uint8_t pad = (sha256->bufLen < 56 ? 56 : 120) - sha256->bufLen;
	SHA256Update(sha256, padding, pad);

	uint8_t len8[8];
	len8[7] = (len >>  0) & 0xFF;
	len8[6] = (len >>  8) & 0xFF;
	len8[5] = (len >> 16) & 0xFF;
	len8[4] = (len >> 24) & 0xFF;
	len8[3] = (len >> 32) & 0xFF;
	len8[2] = (len >> 40) & 0xFF;
	len8[1] = (len >> 48) & 0xFF;
	len8[0] = (len >> 56) & 0xFF;
	SHA256Update(sha256, len8, 8);

	u32to8(sha256->H[0], dst +  0);
	u32to8(sha256->H[1], dst +  4);
	u32to8(sha256->H[2], dst +  8);
	u32to8(sha256->H[3], dst + 12);
	u32to8(sha256->H[4], dst + 16);
	u32to8(sha256->H[5], dst + 20);
	u32to8(sha256->H[6], dst + 24);
	u32to8(sha256->H[7], dst + 28);

	// TODO : true cleaning
}

void SHA256(uint8_t dst[32], const uint8_t* src, uint64_t slen)
{
	SHA256_CTX sha256;
	SHA256Init  (&sha256);
	SHA256Update(&sha256, src, slen);
	SHA256Final (&sha256, dst);
}



static const SHA224_CTX initctx224 =
{
	0, 0, {0},
	{0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4},
};

void SHA224Init(SHA224_CTX* sha224)
{
	memcpy(sha224, &initctx224, sizeof(SHA224_CTX));
}

void SHA224Block(SHA224_CTX* sha224, const uint8_t block[64])
{
	SHA256Block(sha224, block);
}

void SHA224Update(SHA224_CTX* sha224, const uint8_t* data, uint64_t len)
{
	SHA256Update(sha224, data, len);
}

void SHA224Final(SHA224_CTX* sha224, uint8_t dst[28])
{
	uint64_t len = sha224->len << 3;
	uint8_t pad = (sha224->bufLen < 56 ? 56 : 120) - sha224->bufLen;
	SHA224Update(sha224, padding, pad);

	uint8_t len8[8];
	len8[7] = (len >>  0) & 0xFF;
	len8[6] = (len >>  8) & 0xFF;
	len8[5] = (len >> 16) & 0xFF;
	len8[4] = (len >> 24) & 0xFF;
	len8[3] = (len >> 32) & 0xFF;
	len8[2] = (len >> 40) & 0xFF;
	len8[1] = (len >> 48) & 0xFF;
	len8[0] = (len >> 56) & 0xFF;
	SHA224Update(sha224, len8, 8);

	u32to8(sha224->H[0], dst +  0);
	u32to8(sha224->H[1], dst +  4);
	u32to8(sha224->H[2], dst +  8);
	u32to8(sha224->H[3], dst + 12);
	u32to8(sha224->H[4], dst + 16);
	u32to8(sha224->H[5], dst + 20);
	u32to8(sha224->H[6], dst + 24);
	//u32to8(sha224->H[7], dst + 28);

	// TODO : true cleaning
}

void SHA224(uint8_t dst[28], const uint8_t* src, uint64_t slen)
{
	SHA224_CTX sha224;
	SHA224Init  (&sha224);
	SHA224Update(&sha224, src, slen);
	SHA224Final (&sha224, dst);
}
