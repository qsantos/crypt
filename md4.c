// Reference:
// RFC 1320
#include "md4.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t* padding = (uint8_t*)
	"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

MD4ctx* MD4_new()
{
	MD4ctx* ret = malloc(sizeof(MD4ctx));
	ret->bufLen = 0;
	ret->A = 0x67452301;
	ret->B = 0xEFCDAB89;
	ret->C = 0x98BADCFE;
	ret->D = 0x10325476;
	ret->len = 0;
	return ret;
}

#define F(X,Y,Z) (((X) & (Y)) | (~(X) & (Z)))
#define G(X,Y,Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define ROT(x,n) ((x) << n) | ((x) >> (32-n))
#define OP1(a,b,c,d,k,s) md4->a = ROT(md4->a + F(md4->b,md4->c,md4->d) + X[k] + 0x00000000, s);
#define OP2(a,b,c,d,k,s) md4->a = ROT(md4->a + G(md4->b,md4->c,md4->d) + X[k] + 0x5A827999, s);
#define OP3(a,b,c,d,k,s) md4->a = ROT(md4->a + H(md4->b,md4->c,md4->d) + X[k] + 0x6ED9EBA1, s);
static void MD4_block(MD4ctx* md4, const uint8_t block[64])
{
	uint32_t X[16];
	for (uint8_t i = 0; i < 16; i++)
		X[i] = (block[i*4] << 0) | (block[i*4+1] << 8) | (block[i*4+2] << 16) | (block[i*4+3] << 24);
	
	uint32_t AA = md4->A;
	uint32_t BB = md4->B;
	uint32_t CC = md4->C;
	uint32_t DD = md4->D;
	
	OP1(A,B,C,D,  0, 3)  OP1(D,A,B,C,  1, 7)  OP1(C,D,A,B,  2,11)  OP1(B,C,D,A,  3,19)
	OP1(A,B,C,D,  4, 3)  OP1(D,A,B,C,  5, 7)  OP1(C,D,A,B,  6,11)  OP1(B,C,D,A,  7,19)
	OP1(A,B,C,D,  8, 3)  OP1(D,A,B,C,  9, 7)  OP1(C,D,A,B, 10,11)  OP1(B,C,D,A, 11,19)
	OP1(A,B,C,D, 12, 3)  OP1(D,A,B,C, 13, 7)  OP1(C,D,A,B, 14,11)  OP1(B,C,D,A, 15,19)
	
	OP2(A,B,C,D,  0, 3)  OP2(D,A,B,C,  4, 5)  OP2(C,D,A,B,  8, 9)  OP2(B,C,D,A, 12,13)
	OP2(A,B,C,D,  1, 3)  OP2(D,A,B,C,  5, 5)  OP2(C,D,A,B,  9, 9)  OP2(B,C,D,A, 13,13)
	OP2(A,B,C,D,  2, 3)  OP2(D,A,B,C,  6, 5)  OP2(C,D,A,B, 10, 9)  OP2(B,C,D,A, 14,13)
	OP2(A,B,C,D,  3, 3)  OP2(D,A,B,C,  7, 5)  OP2(C,D,A,B, 11, 9)  OP2(B,C,D,A, 15,13)
	
	OP3(A,B,C,D,  0, 3)  OP3(D,A,B,C,  8, 9)  OP3(C,D,A,B,  4,11)  OP3(B,C,D,A, 12,15)
	OP3(A,B,C,D,  2, 3)  OP3(D,A,B,C, 10, 9)  OP3(C,D,A,B,  6,11)  OP3(B,C,D,A, 14,15)
	OP3(A,B,C,D,  1, 3)  OP3(D,A,B,C,  9, 9)  OP3(C,D,A,B,  5,11)  OP3(B,C,D,A, 13,15)
	OP3(A,B,C,D,  3, 3)  OP3(D,A,B,C, 11, 9)  OP3(C,D,A,B,  7,11)  OP3(B,C,D,A, 15,15)
	
	md4->A += AA;
	md4->B += BB;
	md4->C += CC;
	md4->D += DD;
	
	memset(X, 0, 16);
	AA = 0;
	BB = 0;
	CC = 0;
	DD = 0;
}

void MD4_push(MD4ctx* md4, uint64_t len, const uint8_t* data)
{
	uint32_t i = 0;
	uint8_t availBuf = 64 - md4->bufLen;
	if (len >= availBuf)
	{
		memcpy(md4->buffer + md4->bufLen, data, availBuf);
		MD4_block(md4, md4->buffer);
		i = availBuf;
		md4->bufLen = 0;
		
		while (i + 63 < len)
		{
			MD4_block(md4, data + i);
			i+= 64;
		}
	}
	memcpy(md4->buffer + md4->bufLen, data + i, len - i);
	md4->bufLen += len - i;
	md4->len += len;
	
	i = 0;
	availBuf = 0;
}

static void u32to8(uint32_t v, uint8_t* dst)
{
	dst[0] = (v >>  0) & 0xFF;
	dst[1] = (v >>  8) & 0xFF;
	dst[2] = (v >> 16) & 0xFF;
	dst[3] = (v >> 24) & 0xFF;
	v = 0;
}

void MD4_hash(MD4ctx* md4, uint8_t dst[16])
{
	uint64_t len = md4->len << 3;
	uint8_t pad = (md4->bufLen < 56 ? 56 : 120) - md4->bufLen;
	MD4_push(md4, pad, padding);
	
	uint8_t len8[8];
	len8[0] = (len >>  0) & 0xFF;
	len8[1] = (len >>  8) & 0xFF;
	len8[2] = (len >> 16) & 0xFF;
	len8[3] = (len >> 24) & 0xFF;
	len8[4] = (len >> 32) & 0xFF;
	len8[5] = (len >> 40) & 0xFF;
	len8[6] = (len >> 48) & 0xFF;
	len8[7] = (len >> 56) & 0xFF;
	MD4_push(md4, 8, len8);
	
	u32to8(md4->A, dst +  0);
	u32to8(md4->B, dst +  4);
	u32to8(md4->C, dst +  8);
	u32to8(md4->D, dst + 12);
	
	len = 0;
	pad = 0;
	memset(len8, 0, 8);
	md4->bufLen = 0;
	memset(md4->buffer, 0, 64);
	md4->A = 0;
	md4->B = 0;
	md4->C = 0;
	md4->D = 0;
	md4->len = 0;
	free(md4);
}

void MD4(uint64_t len, const uint8_t* src, uint8_t dst[16])
{
	MD4ctx* md4 = MD4_new();
	MD4_push(md4, len, src);
	MD4_hash(md4, dst);
}
