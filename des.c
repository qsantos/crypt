/*\
 *  This is an awesome programm simulating awesome battles of awesome robot tanks
 *  Copyright (C) 2012  Quentin SANTOS
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
\*/

// Reference:
// Federal Information Processing Standards Publication
// (FIPS PUB) 46-3, Data Encryption Standard, 25 October 1999.
#include "des.h"

#include <string.h>

static const uint8_t IP[] =
{
	57, 49, 41, 33, 25, 17,  9,  1,
	59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5,
	63, 55, 47, 39, 31, 23, 15,  7,
	56, 48, 40, 32, 24, 16,  8,  0,
	58, 50, 42, 34, 26, 18, 10,  2,
	60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6,
};

static const uint8_t IPR[] =
{
	39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30,
	37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28,
	35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26,
	33,  1, 41,  9, 49, 17, 57, 25,
	32,  0, 40,  8, 48, 16, 56, 24,
};

static const uint8_t E[] =
{
	31,  0,  1,  2,  3,  4,
	 3,  4,  5,  6,  7,  8,
	 7,  8,  9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31,  0,
};

static const uint8_t S[] =
{
	14,  0,  4, 15, 13,  7,  1,  4,   2, 14, 15,  2, 11, 13,  8,  1,
	 3, 10, 10,  6,  6, 12, 12, 11,   5,  9,  9,  5,  0,  3,  7,  8,
	 4, 15,  1, 12, 14,  8,  8,  2,  13,  4,  6,  9,  2,  1, 11,  7,
	15,  5, 12, 11,  9,  3,  7, 14,   3, 10, 10,  0,  5,  6,  0, 13,

	15,  3,  1, 13,  8,  4, 14,  7,   6, 15, 11,  2,  3,  8,  4, 14,
	 9, 12,  7,  0,  2,  1, 13, 10,  12,  6,  0,  9,  5, 11, 10,  5,
	 0, 13, 14,  8,  7, 10, 11,  1,  10,  3,  4, 15, 13,  4,  1,  2,
	 5, 11,  8,  6, 12,  7,  6, 12,   9,  0,  3,  5,  2, 14, 15,  9,

	10, 13,  0,  7,  9,  0, 14,  9,   6,  3,  3,  4, 15,  6,  5, 10,
	 1,  2, 13,  8, 12,  5,  7, 14,  11, 12,  4, 11,  2, 15,  8,  1,
	13,  1,  6, 10,  4, 13,  9,  0,   8,  6, 15,  9,  3,  8,  0,  7,
	11,  4,  1, 15,  2, 14, 12,  3,   5, 11, 10,  5, 14,  2,  7, 12,

	 7, 13, 13,  8, 14, 11,  3,  5,   0,  6,  6, 15,  9,  0, 10,  3,
	 1,  4,  2,  7,  8,  2,  5, 12,  11,  1, 12, 10,  4, 14, 15,  9,
	10,  3,  6, 15,  9,  0,  0,  6,  12, 10, 11,  1,  7, 13, 13,  8,
	15,  9,  1,  4,  3,  5, 14, 11,   5, 12,  2,  7,  8,  2,  4, 14,

	 2, 14, 12, 11,  4,  2,  1, 12,   7,  4, 10,  7, 11, 13,  6,  1,
	 8,  5,  5,  0,  3, 15, 15, 10,  13,  3,  0,  9, 14,  8,  9,  6,
	 4, 11,  2,  8,  1, 12, 11,  7,  10,  1, 13, 14,  7,  2,  8, 13,
	15,  6,  9, 15, 12,  0,  5,  9,   6, 10,  3,  4,  0,  5, 14,  3,

	12, 10,  1, 15, 10,  4, 15,  2,   9,  7,  2, 12,  6,  9,  8,  5,
	 0,  6, 13,  1,  3, 13,  4, 14,  14,  0,  7, 11,  5,  3, 11,  8,
	 9,  4, 14,  3, 15,  2,  5, 12,   2,  9,  8,  5, 12, 15,  3, 10,
	 7, 11,  0, 14,  4,  1, 10,  7,   1,  6, 13,  0, 11,  8,  6, 13,

	 4, 13, 11,  0,  2, 11, 14,  7,  15,  4,  0,  9,  8,  1, 13, 10,
	 3, 14, 12,  3,  9,  5,  7, 12,   5,  2, 10, 15,  6,  8,  1,  6,
	 1,  6,  4, 11, 11, 13, 13,  8,  12,  1,  3,  4,  7, 10, 14,  7,
	10,  9, 15,  5,  6,  0,  8, 15,   0, 14,  5,  2,  9,  3,  2, 12,

	13,  1,  2, 15,  8, 13,  4,  8,   6, 10, 15,  3, 11,  7,  1,  4,
	10, 12,  9,  5,  3,  6, 14, 11,   5,  0,  0, 14, 12,  9,  7,  2,
	 7,  2, 11,  1,  4, 14,  1,  7,   9,  4, 12, 10, 14,  8,  2, 13,
	 0, 15,  6, 12, 10,  9, 13,  0,  15,  3,  3,  5,  5,  6,  8, 11,

};

static const uint8_t P[] =
{
	15,  6, 19, 20,
	28, 11, 27, 16,
	 0, 14, 22, 25,
	 4, 17, 30,  9,
	 1,  7, 23, 13,
	31, 26,  2,  8,
	18, 12, 29,  5,
	21, 10,  3, 24,
	56, 48, 40, 32,
	24, 16,  8,  0,
	57, 49, 41, 33,
	25, 17,  9,  1,
};

static const uint8_t PC1[] =
{
	56, 48, 40, 32, 24, 16,  8,
	 0, 57, 49, 41, 33, 25, 17,
	 9,  1, 58, 50, 42, 34, 26,
	18, 10,  2, 59, 51, 43, 35,
	62, 54, 46, 38, 30, 22, 14,
	 6, 61, 53, 45, 37, 29, 21,
	13,  5, 60, 52, 44, 36, 28,
	20, 12,  4, 27, 19, 11,  3,
};
static const uint8_t PC2[] =
{
	13, 16, 10, 23,  0,  4,
	 2, 27, 14,  5, 20,  9,
	22, 18, 11,  3, 25,  7,
	15,  6, 26, 19, 12,  1,
	40, 51, 30, 36, 46, 54,
	29, 39, 50, 44, 32, 47,
	43, 48, 38, 55, 33, 52,
	45, 41, 49, 35, 28, 31,
};

static const uint8_t shifts[] =
{
	1, 1, 2, 2,
	2, 2, 2, 2,
	1, 2, 2, 2,
	2, 2, 2, 1,
};

static void permute(const uint8_t* P, uint8_t len, const uint8_t* in, uint8_t* out)
{
	uint8_t b = 0;
	for (uint8_t i = 0; i < len; i++)
	{
		uint8_t v = 0;
		for (uint8_t j = 0; j < 8; j++)
		{
			uint8_t bit = P[b];
			v |= ( (in[bit/8] << (bit%8)) & 0x80 ) >> j;
			b++;
		}
		out[i] = v;
	}
}

static void f(uint8_t R[4], uint8_t K[6], uint8_t out[4])
{
	uint8_t cur[6];
	permute(E, 6, R, cur);
	for (uint8_t i = 0; i < 6; i++)
		cur[i] ^= K[i];

	const uint8_t B[] =
	{
		cur[0] >> 2,
		(cur[0] & 0x03) << 4 | (cur[1] >> 4),
		(cur[1] & 0x0F) << 2 | (cur[2] >> 6),
		cur[2] & 0x3F,
		cur[3] >> 2,
		(cur[3] & 0x03) << 4 | (cur[4] >> 4),
		(cur[4] & 0x0F) << 2 | (cur[5] >> 6),
		cur[5] & 0x3F,
	};
	uint8_t s = 0;
	for (uint8_t i = 0; i < 4; i++)
	{
		cur[i]  = S[s << 6 | B[s]] << 4; s++;
		cur[i] |= S[s << 6 | B[s]]; s++;
	}

	permute(P, 4, cur, out);
}

#define CD_LSHIFT(C,s) C = ((C << s) | (C >> (28-s))) & 0xFFFFFFF
#define CD_RSHIFT(C,s) C = ((C >> s) | (C << (28-s))) & 0xFFFFFFF
void DES(const uint8_t key[7], const uint8_t in[8], uint8_t out[8], bool inverse)
{
	uint8_t p = 0;
	uint8_t LR[2][8];
	permute(IP, 8, in, LR[p]);

	uint8_t CD[7];
	permute(PC1, 7, key, CD);
	uint32_t C = (CD[0] << 20)         | (CD[1] << 12) | (CD[2] << 4) | (CD[3] >> 4);
	uint32_t D = ((CD[3] & 0xF) << 24) | (CD[4] << 16) | (CD[5] << 8) | (CD[6] << 0);
	for (uint8_t i = 0; i < 16; i++)
	{
		if (!inverse)
		{
			CD_LSHIFT(C, shifts[i]);
			CD_LSHIFT(D, shifts[i]);
		}
		CD[0] = C >> 20;
		CD[1] = C >> 12;
		CD[2] = C >> 4;
		CD[3] = ((C & 0xF) << 4) | (D >> 24);
		CD[4] = D >> 16;
		CD[5] = D >> 8;
		CD[6] = D >> 0;
		uint8_t K[6];
		permute(PC2, 6, CD, K);
		if (inverse)
		{
			CD_RSHIFT(C, shifts[15-i]);
			CD_RSHIFT(D, shifts[15-i]);
		}

		memcpy(LR[1-p], LR[p] + 4, 4);
		f(LR[p] + 4, K, LR[1-p] + 4);
		for (uint8_t i = 0; i < 4; i++)
			LR[1-p][i+4] ^= LR[p][i];
		p = 1 - p;
	}

	memcpy(LR[1-p], LR[p] + 4, 4);
	memcpy(LR[1-p] + 4, LR[p], 4);
	p = 1 - p;

	permute(IPR, 8, LR[p], out);
}
