// Reference:
// Federal Information Processing Standards Publication
// (FIPS PUB) 180-2, Secure Hash Standard, 1 August 2002.
#include "sha512.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t* padding = (uint8_t*)
	"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
;

static const uint64_t K[] =
{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

static const SHA512_CTX initctx512 =
{
	0, {0},
	{ 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 },
	{0, 0}
};

void SHA512Init(SHA512_CTX* sha512)
{
	memcpy(sha512, &initctx512, sizeof(SHA512_CTX));
}

static uint64_t Ch (uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (~x & z);          }
static uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) | (x & z) | (y & z); }
#define ROTL(x,n) (((x) << n) | ((x) >> (64-n)))
#define ROTR(x,n) (((x) >> n) | ((x) << (64-n)))
#define  SHR(x,n) ((x) >> n)
static uint64_t Sum0  (uint64_t x) { return ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39); }
static uint64_t Sum1  (uint64_t x) { return ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41); }
static uint64_t Sigma0(uint64_t x) { return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR (x, 7); }
static uint64_t Sigma1(uint64_t x) { return ROTR(x,19) ^ ROTR(x,61) ^ SHR (x, 6); }
#define B64(i) ((uint64_t)(block[t*8+i]))
static void SHA512_block(SHA512_CTX* sha512, const uint8_t block[128])
{
	uint64_t W[80];
	for (uint8_t t = 0; t < 16; t++)
		W[t] = (B64(0) << 56) | (B64(1) << 48) | (B64(2) << 40) | (B64(3) << 32)
		     | (B64(4) << 24) | (B64(5) << 16) | (B64(6) <<  8) | (B64(7) <<  0);

	for (uint8_t t = 16; t < 80; t++)
		W[t] = Sigma1(W[t-2]) + W[t-7] + Sigma0(W[t-15]) + W[t-16];

	uint64_t a = sha512->H[0];
	uint64_t b = sha512->H[1];
	uint64_t c = sha512->H[2];
	uint64_t d = sha512->H[3];
	uint64_t e = sha512->H[4];
	uint64_t f = sha512->H[5];
	uint64_t g = sha512->H[6];
	uint64_t h = sha512->H[7];

	uint64_t T1;
	uint64_t T2;
	for (uint8_t t = 0; t < 80; t++)
	{
		T1 = h + Sum1(e) + Ch (e,f,g) + K[t] + W[t];
		T2 =     Sum0(a) + Maj(a,b,c);
		h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
	}

	sha512->H[0] += a;
	sha512->H[1] += b;
	sha512->H[2] += c;
	sha512->H[3] += d;
	sha512->H[4] += e;
	sha512->H[5] += f;
	sha512->H[6] += g;
	sha512->H[7] += h;

	// TODO : true cleaning
/*
	T1 = 0;
	T2 = 0;
	memset(W, 0, 80);
	a = 0;
	b = 0;
	c = 0;
	d = 0;
	e = 0;
	f = 0;
	g = 0;
*/
}

void SHA512Update(SHA512_CTX* sha512, uint64_t len, const uint8_t* data)
{
	uint64_t i = 0;
	uint8_t availBuf = 128 - sha512->bufLen;
	if (len >= availBuf)
	{
		memcpy(sha512->buffer + sha512->bufLen, data, availBuf);
		SHA512_block(sha512, sha512->buffer);
		i = availBuf;
		sha512->bufLen = 0;

		while (i + 127 < len)
		{
			SHA512_block(sha512, data + i);
			i+= 128;
		}
	}
	memcpy(sha512->buffer + sha512->bufLen, data + i, len - i);
	sha512->bufLen += len - i;

	// TODO
	uint64_t bits = len << 3;
	sha512->len[0] += bits;


	// TODO : true cleaning
/*
	i = 0;
	availBuf = 0;
	bits = 0;
*/
}

static void u64to8(uint64_t v, uint8_t* dst)
{
	dst[0] = (v >> 56) & 0xFF;
	dst[1] = (v >> 48) & 0xFF;
	dst[2] = (v >> 40) & 0xFF;
	dst[3] = (v >> 32) & 0xFF;
	dst[4] = (v >> 24) & 0xFF;
	dst[5] = (v >> 16) & 0xFF;
	dst[6] = (v >>  8) & 0xFF;
	dst[7] = (v >>  0) & 0xFF;

	v = 0;
}

void SHA512Final(SHA512_CTX* sha512, uint8_t dst[32])
{
	uint64_t len0 = sha512->len[0];
	uint64_t len1 = sha512->len[1];
	uint8_t pad = (sha512->bufLen < 112 ? 112 : 240) - sha512->bufLen;
	SHA512Update(sha512, pad, padding);

	uint8_t len8[16];
	len8[15] = (len0 >>  0) & 0xFF;
	len8[14] = (len0 >>  8) & 0xFF;
	len8[13] = (len0 >> 16) & 0xFF;
	len8[12] = (len0 >> 24) & 0xFF;
	len8[11] = (len0 >> 32) & 0xFF;
	len8[10] = (len0 >> 40) & 0xFF;
	len8[ 9] = (len0 >> 48) & 0xFF;
	len8[ 8] = (len0 >> 56) & 0xFF;
	len8[ 7] = (len1 >>  0) & 0xFF;
	len8[ 6] = (len1 >>  8) & 0xFF;
	len8[ 5] = (len1 >> 16) & 0xFF;
	len8[ 4] = (len1 >> 24) & 0xFF;
	len8[ 3] = (len1 >> 32) & 0xFF;
	len8[ 2] = (len1 >> 40) & 0xFF;
	len8[ 1] = (len1 >> 48) & 0xFF;
	len8[ 0] = (len1 >> 56) & 0xFF;
	SHA512Update(sha512, 16, len8);

	u64to8(sha512->H[0], dst +  0);
	u64to8(sha512->H[1], dst +  8);
	u64to8(sha512->H[2], dst + 16);
	u64to8(sha512->H[3], dst + 24);
	u64to8(sha512->H[4], dst + 32);
	u64to8(sha512->H[5], dst + 40);
	u64to8(sha512->H[6], dst + 48);
	u64to8(sha512->H[7], dst + 56);

	// TODO : true cleaning
/*
	len0 = 0;
	len1 = 0;
	pad = 0;
	memset(len8, 0, 16);
	sha512->bufLen = 0;
	memset(sha512->buffer, 0, 128);
	memset(sha512->H, 0, 8);
	memset(sha512->len, 0, 2);
*/
}

void SHA512(uint64_t slen, const uint8_t* src, uint8_t dst[32])
{
	SHA512_CTX sha512;
	SHA512Init  (&sha512);
	SHA512Update(&sha512, slen, src);
	SHA512Final (&sha512, dst);
}



static const SHA384_CTX initctx384 =
{
	0, {0},
	{ 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4},
	{0, 0}
};

void SHA384Init(SHA384_CTX* sha384)
{
	memcpy(sha384, &initctx384, sizeof(SHA384_CTX));
}

void SHA384Update(SHA384_CTX* sha384, uint64_t len, const uint8_t* data)
{
	SHA512Update(sha384, len, data);
}

void SHA384Final(SHA384_CTX* sha384, uint8_t dst[32])
{
	uint64_t len0 = sha384->len[0];
	uint64_t len1 = sha384->len[1];
	uint8_t pad = (sha384->bufLen < 112 ? 112 : 240) - sha384->bufLen;
	SHA384Update(sha384, pad, padding);

	uint8_t len8[16];
	len8[15] = (len0 >>  0) & 0xFF;
	len8[14] = (len0 >>  8) & 0xFF;
	len8[13] = (len0 >> 16) & 0xFF;
	len8[12] = (len0 >> 24) & 0xFF;
	len8[11] = (len0 >> 32) & 0xFF;
	len8[10] = (len0 >> 40) & 0xFF;
	len8[ 9] = (len0 >> 48) & 0xFF;
	len8[ 8] = (len0 >> 56) & 0xFF;
	len8[ 7] = (len1 >>  0) & 0xFF;
	len8[ 6] = (len1 >>  8) & 0xFF;
	len8[ 5] = (len1 >> 16) & 0xFF;
	len8[ 4] = (len1 >> 24) & 0xFF;
	len8[ 3] = (len1 >> 32) & 0xFF;
	len8[ 2] = (len1 >> 40) & 0xFF;
	len8[ 1] = (len1 >> 48) & 0xFF;
	len8[ 0] = (len1 >> 56) & 0xFF;
	SHA384Update(sha384, 16, len8);

	u64to8(sha384->H[0], dst +  0);
	u64to8(sha384->H[1], dst +  8);
	u64to8(sha384->H[2], dst + 16);
	u64to8(sha384->H[3], dst + 24);
	u64to8(sha384->H[4], dst + 32);
	u64to8(sha384->H[5], dst + 40);
	//u64to8(sha384->H[6], dst + 48);
	//u64to8(sha384->H[7], dst + 56);

	// TODO : true cleaning
/*
	len0 = 0;
	len1 = 0;
	pad = 0;
	memset(len8, 0, 16);
	sha384->bufLen = 0;
	memset(sha384->buffer, 0, 128);
	memset(sha384->H, 0, 8);
	memset(sha384->len, 0, 2);
*/
}

void SHA384(uint64_t slen, const uint8_t* src, uint8_t dst[32])
{
	SHA384_CTX sha384;
	SHA384Init  (&sha384);
	SHA384Update(&sha384, slen, src);
	SHA384Final (&sha384, dst);
}
