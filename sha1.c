// Reference:
// RFC 3174
#include "sha1.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t* padding = (uint8_t*)
	"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

SHA1ctx* SHA1_new()
{
	SHA1ctx* ret = malloc(sizeof(SHA1ctx));
	ret->bufLen = 0;
	ret->H[0] = 0x67452301;
	ret->H[1] = 0xEFCDAB89;
	ret->H[2] = 0x98BADCFE;
	ret->H[3] = 0x10325476;
	ret->H[4] = 0xC3D2E1F0;
	ret->len = 0;
	return ret;
}

#define F(B,C,D) (((B) & (C)) | (~(B) & (D)))
#define G(B,C,D) ((B) ^ (C) ^ (D))
#define H(B,C,D) (((B) & (C)) | ((B) & (D)) | ((C) & (D)))
#define ROT(x,n) (((x) << n) | ((x) >> (32-n)))
#define OP(f,K) \
{ \
	uint32_t TEMP = ROT(A,5) + f(B,C,D) + E + W[t] + K; \
	E = D; D = C; C = ROT(B, 30); B = A; A = TEMP; \
	TEMP = 0; \
}
static void SHA1_block(SHA1ctx* sha1, const uint8_t block[64])
{
	uint32_t W[80];
	for (uint8_t t = 0; t < 16; t++)
		W[t] = (block[t*4] << 24) | (block[t*4+1] << 16) | (block[t*4+2] << 8) | (block[t*4+3] << 0);
	
	for (uint8_t t = 16; t < 80; t++)
		W[t] = ROT(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
	
	uint32_t A = sha1->H[0];
	uint32_t B = sha1->H[1];
	uint32_t C = sha1->H[2];
	uint32_t D = sha1->H[3];
	uint32_t E = sha1->H[4];
	
	for (uint8_t t =  0; t < 20; t++)
		OP(F, 0x5A827999);
	for (uint8_t t = 20; t < 40; t++)
		OP(G, 0x6ED9EBA1);
	for (uint8_t t = 40; t < 60; t++)
		OP(H, 0x8F1BBCDC);
	for (uint8_t t = 60; t < 80; t++)
		OP(G, 0xCA62C1D6);
	
	sha1->H[0] += A;
	sha1->H[1] += B;
	sha1->H[2] += C;
	sha1->H[3] += D;
	sha1->H[4] += E;
	
	memset(W, 0, 80);
	A = 0;
	B = 0;
	C = 0;
	D = 0;
	E = 0;
}

void SHA1_push(SHA1ctx* sha1, uint64_t len, const uint8_t* data)
{
	uint32_t i = 0;
	uint8_t availBuf = 64 - sha1->bufLen;
	if (len >= availBuf)
	{
		memcpy(sha1->buffer + sha1->bufLen, data, availBuf);
		SHA1_block(sha1, sha1->buffer);
		i = availBuf;
		sha1->bufLen = 0;
		
		while (i + 63 < len)
		{
			SHA1_block(sha1, data + i);
			i+= 64;
		}
	}
	memcpy(sha1->buffer + sha1->bufLen, data + i, len - i);
	sha1->bufLen += len - i;
	sha1->len += len;
	
	i = 0;
	availBuf = 0;
}

static void u32to8(uint32_t v, uint8_t* dst)
{
	dst[0] = (v >> 24) & 0xFF;
	dst[1] = (v >> 16) & 0xFF;
	dst[2] = (v >>  8) & 0xFF;
	dst[3] = (v >>  0) & 0xFF;
	
	v = 0;
}

void SHA1_hash(SHA1ctx* sha1, uint8_t dst[20])
{
	uint64_t len = sha1->len << 3;
	uint8_t pad = (sha1->bufLen < 56 ? 56 : 120) - sha1->bufLen;
	SHA1_push(sha1, pad, padding);
	
	uint8_t len8[8];
	len8[7] = (len >>  0) & 0xFF;
	len8[6] = (len >>  8) & 0xFF;
	len8[5] = (len >> 16) & 0xFF;
	len8[4] = (len >> 24) & 0xFF;
	len8[3] = (len >> 32) & 0xFF;
	len8[2] = (len >> 40) & 0xFF;
	len8[1] = (len >> 48) & 0xFF;
	len8[0] = (len >> 56) & 0xFF;
	SHA1_push(sha1, 8, len8);
	
	u32to8(sha1->H[0], dst +  0);
	u32to8(sha1->H[1], dst +  4);
	u32to8(sha1->H[2], dst +  8);
	u32to8(sha1->H[3], dst + 12);
	u32to8(sha1->H[4], dst + 16);
	
	len = 0;
	pad = 0;
	memset(len8, 0, 8);
	sha1->bufLen = 0;
	memset(sha1->buffer, 0, 64);
	memset(sha1->H, 0, 5);
	sha1->len = 0;
	free(sha1);
}

void SHA1(uint64_t len, const uint8_t* src, uint8_t dst[20])
{
	SHA1ctx* sha1 = SHA1_new();
	SHA1_push(sha1, len, src);
	SHA1_hash(sha1, dst);
}
