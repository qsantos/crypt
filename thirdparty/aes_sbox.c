#include <stdint.h>
#include <stdio.h>

#define M (0x011B) // irreductible polynomial
#define ROTR(x,n) (((x) >> n) | ((x) << (8-n)))

static uint32_t prod8(uint32_t a, uint32_t b)
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

static uint32_t mod8(uint32_t a, uint32_t b)
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

/*
static uint8_t dot8(uint8_t a, uint8_t b)
{
	return mod8(prod8(a, b), M);
}
*/

/*
static uint32_t prod32(uint32_t a, uint32_t b)
{
	uint32_t d = 0;
	d |= dot8(a&0xF000,b&0x000F)^dot8(a&0x000F,b&0x00F0)^dot8(a&0x00F0,b&0x0F00)^dot8(a&0x0F00,b&0xF000);
	d <<= 4;
	d |= dot8(a&0x0F00,b&0x000F)^dot8(a&0xF000,b&0x00F0)^dot8(a&0x000F,b&0x0F00)^dot8(a&0x00F0,b&0xF000);
	d <<= 4;
	d |= dot8(a&0x00F0,b&0x000F)^dot8(a&0x0F00,b&0x00F0)^dot8(a&0xF000,b&0x0F00)^dot8(a&0x000F,b&0xF000);
	d <<= 4;
	d |= dot8(a&0x000F,b&0x000F)^dot8(a&0x00F0,b&0x00F0)^dot8(a&0x0F00,b&0x0F00)^dot8(a&0xF000,b&0xF000);
	return d;
}
*/

static int comp(uint32_t a, uint32_t b)
{
	while (a)
	{
		if (!b)
			return 1;
		a >>= 1;
		b >>= 1;
	}
	return b ? -1 : 0;
}

#define COMP_DEF(A, B)
static void division(uint32_t a, uint32_t b, uint32_t* q, uint32_t* r)
{
	uint32_t bb = b;
	while (comp(a, b) > 0)
		b <<= 1;

	*q = 0;
	while (b >= bb)
	{
		*q <<= 1;
		if (comp(a, b) == 0)
		{
			a ^= b;
			*q |= 1;
		}
		b >>= 1;
	}
	*r = a;
}

// Reference:
// A. Menezes, P. van Oorschot, and S. Vanstone, Handbook of Applied Cryptography,
// CRC Press, New York, 1997, p. 81-83.
static void euclide(uint32_t g, uint32_t h, uint32_t* s, uint32_t* t)
{
	if (h == 0)
	{
		*s = 1;
		*t = 0;
		return;
	}

	uint32_t s1 = 0;
	uint32_t s2 = 1;
	uint32_t t1 = 1;
	uint32_t t2 = 0;
	while (h)
	{
		uint32_t q, r;
		division(g, h, &q, &r);
		*s = s2 ^ prod8(q, s1);
		*t = t2 ^ prod8(q, t1);
		g = h;
		h = r;
		s2 = s1;
		s1 = *s;
		t2 = t1;
		t1 = *t;
	}
	*s = s2;
	*t = t2;
}

static uint8_t inverse(uint8_t b)
{
	if (!b)
		return 0;

	uint32_t a;
	uint32_t c;
	euclide(b, M, &a, &c);
	return mod8(a, M);
}

int main(int argc, char** argv)
{
	(void) argc;
	(void) argv;

	printf("uint8_t SBox[] =\n");
	printf("{\n");
	for (uint32_t i = 0; i < 256; )
	{
		printf("\t");
		for (uint8_t j = 0; j < 16; j++, i++)
		{
			uint8_t b = inverse(i);
			b = b ^ ROTR(b,4) ^ ROTR(b,5) ^ ROTR(b,6) ^ ROTR(b,7) ^ 0x63;
			printf("0x%.2x, ", b);
		}
		printf("\n");
	}
	printf("};\n");

	return 0;
}