// Reference:
// RFC 1319
#include "md2.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static uint8_t S[256] =
{
	0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01,  0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
	0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C,  0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
	0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16,  0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
	0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49,  0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
	0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F,  0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
	0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27,  0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
	0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1,  0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
	0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6,  0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
	0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20,  0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
	0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6,  0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
	0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A,  0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
	0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09,  0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
	0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA,  0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
	0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D,  0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
	0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4,  0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
	0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A,  0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
};

static uint8_t* padding[] =
{
	(uint8_t*)"",
	(uint8_t*)"\x01",
	(uint8_t*)"\x02\x02",
	(uint8_t*)"\x03\x03\x03",
	(uint8_t*)"\x04\x04\x04\x04",
	(uint8_t*)"\x05\x05\x05\x05\x05",
	(uint8_t*)"\x06\x06\x06\x06\x06\x06",
	(uint8_t*)"\x07\x07\x07\x07\x07\x07\x07",
	(uint8_t*)"\x08\x08\x08\x08\x08\x08\x08\x08",
	(uint8_t*)"\x09\x09\x09\x09\x09\x09\x09\x09\x09",
	(uint8_t*)"\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A",
	(uint8_t*)"\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B",
	(uint8_t*)"\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C",
	(uint8_t*)"\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D",
	(uint8_t*)"\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E",
	(uint8_t*)"\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F",
	(uint8_t*)"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
};

void MD2Init(MD2_CTX* md2)
{
	memset(md2, 0, sizeof(MD2_CTX));
}

void MD2_block(MD2_CTX* md2, const uint8_t block[16], bool updateCheckSum)
{
	if (updateCheckSum)
	{
		uint8_t L = md2->C[15];
		for (uint8_t i = 0; i < 16; i++)
			L = md2->C[i] ^= S[block[i] ^ L];
		L = 0;
	}

	uint8_t X[48];
	memcpy(X, md2->X, 16);
	memcpy(X+16, block, 16);

	for (uint8_t i = 0; i < 16; i++)
		X[i+32] = X[i+16] ^ X[i];
	uint8_t t = 0;
	for (uint8_t i = 0; i < 18; i++)
	{
		for (uint8_t j = 0; j < 48; j++)
			t = X[j] ^= S[t];
		t += i;
	}

	memcpy(md2->X, X, 16);

	// TODO : true cleaning
/*
	t = 0;
	memset(X, 0, 48);
*/
}

void MD2Update(MD2_CTX* md2, const uint8_t* data, uint64_t len)
{
	uint32_t i = 0;
	uint8_t availBuf = 16 - md2->bufLen;
	if (len >= availBuf)
	{
		memcpy(md2->buffer + md2->bufLen, data, availBuf);
		MD2_block(md2, md2->buffer, true);
		i = availBuf;
		md2->bufLen = 0;

		while (i + 15 < len)
		{
			MD2_block(md2, data + i, true);
			i+= 16;
		}
	}
	memcpy(md2->buffer + md2->bufLen, data + i, len - i);
	md2->bufLen += len - i;

	// TODO : true cleaning
/*
	availBuf = 0;
	i = 0;
*/
}

void MD2Final(MD2_CTX* md2, uint8_t dst[16])
{
	uint8_t pad = 16 - md2->bufLen;
	MD2Update(md2, padding[pad], pad);
	MD2_block(md2, md2->C, false);
	memcpy(dst, md2->X, 16);

	// TODO : true cleaning
/*
	pad = 0;
	memset(md2, 0, sizeof(MD2_CTX));
*/
}

void MD2(uint8_t dst[16], const uint8_t* src, uint64_t slen)
{
	MD2_CTX md2;
	MD2Init  (&md2);
	MD2Update(&md2, src, slen);
	MD2Final (&md2, dst);
}
