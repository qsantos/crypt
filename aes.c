// Reference:
// Federal Information Processing Standards Publication
// (FIPS PUB) 197, Advanced Encryption Standard, 26 November 2001.
#include "aes.h"

#include <string.h>
#include <stdio.h>
#include <assert.h>

uint32_t prod8(uint32_t a, uint32_t b)
{
	uint32_t r = 0;
	while (a)
	{
		if (a % 2)
			r ^= b;
		a >>= 1;
		b <<= 1;
	}
	return r;
}

uint32_t mod8(uint32_t a, uint32_t b)
{
	// makes a mask for the first bit of a
	uint32_t aa = a;
	uint32_t ma = 1;
	while (aa)
	{
		aa >>= 1;
		ma <<= 1;
	}
	ma >>= 1;
	
	// pads b to a
	aa = a;
	uint32_t bb = b;
	while (bb)
	{
		aa >>= 1;
		bb >>= 1;
	}
	uint32_t pb = b;
	while (aa)
	{
		aa >>= 1;
		pb <<= 1;
	}
	
	// applies xor on a with b to turn bits of a to zero
	while (pb > b)
	{
		if (a & ma)
			a ^= pb;
		pb >>= 1;
		ma >>= 1;
	}
	return a;
}

uint8_t dot8(uint8_t a, uint8_t b)
{
	return mod8(prod8(a, b), 0x11B);
}

uint32_t prod32(uint32_t a, uint32_t b)
{
	uint32_t d = 0;
	d |= dot8(a&0x000F,b&0x000F)^dot8(a&0x00F0,b&0x00F0)^dot8(a&0x0F00,b&0x0F00)^dot8(a&0xF000,b&0xF000)<< 0;
	d |= dot8(a&0x00F0,b&0x000F)^dot8(a&0x0F00,b&0x00F0)^dot8(a&0xF000,b&0x0F00)^dot8(a&0x000F,b&0xF000)<< 4;
	d |= dot8(a&0x0F00,b&0x000F)^dot8(a&0xF000,b&0x00F0)^dot8(a&0x000F,b&0x0F00)^dot8(a&0x00F0,b&0xF000)<< 8;
	d |= dot8(a&0xF000,b&0x000F)^dot8(a&0x000F,b&0x00F0)^dot8(a&0x00F0,b&0x0F00)^dot8(a&0x0F00,b&0xF000)<<16;
	return d;
}

void AES(const uint8_t KEY[16], const uint8_t in[16], uint8_t out[16], bool encipher)
{
	memcpy(out, in, 8);
}
