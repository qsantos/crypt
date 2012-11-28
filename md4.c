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

static const MD4_CTX initctx = { 0, {0}, 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0};

void MD4Init(MD4_CTX* md4)
{
	memcpy(md4, &initctx, sizeof(MD4_CTX));
}

#define F(X,Y,Z) (((X) & (Y)) | (~(X) & (Z)))
#define G(X,Y,Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define ROT(x,n) ((x) << n) | ((x) >> (32-n))
#define OP1(a,b,c,d,k,s) md4->a = ROT(md4->a + F(md4->b,md4->c,md4->d) + X[k] + 0x00000000, s);
#define OP2(a,b,c,d,k,s) md4->a = ROT(md4->a + G(md4->b,md4->c,md4->d) + X[k] + 0x5A827999, s);
#define OP3(a,b,c,d,k,s) md4->a = ROT(md4->a + H(md4->b,md4->c,md4->d) + X[k] + 0x6ED9EBA1, s);
static void MD4_block(MD4_CTX* md4, const uint8_t block[64])
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

	// TODO : true cleaning
/*
	memset(X, 0, 16);
	AA = 0;
	BB = 0;
	CC = 0;
	DD = 0;
*/
}

void MD4Update(MD4_CTX* md4, const uint8_t* data, uint64_t len)
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

	// TODO : true cleaning
/*
	i = 0;
	availBuf = 0;
*/
}

void MD4Final(MD4_CTX* md4, uint8_t dst[16])
{
	uint64_t len = md4->len << 3;
	uint8_t pad = (md4->bufLen < 56 ? 56 : 120) - md4->bufLen;
	MD4Update(md4, padding, pad);
	MD4Update(md4, (uint8_t*) &len, 8);

	memcpy(dst +  0, &md4->A, 4);
	memcpy(dst +  4, &md4->B, 4);
	memcpy(dst +  8, &md4->C, 4);
	memcpy(dst + 12, &md4->D, 4);

	// TODO : true cleaning
/*
	len = 0;
	pad = 0;
	memset(md4, 0, sizeof(MD4_CTX));
*/
}

void MD4(uint8_t dst[16], const uint8_t* src, uint64_t slen)
{
	MD4_CTX md4;
	MD4Init  (&md4);
	MD4Update(&md4, src, slen);
	MD4Final (&md4, dst);
}
