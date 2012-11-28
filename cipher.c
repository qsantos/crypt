#include "cipher.h"

#include <string.h>

#include "des.h"
#include "aes.h"

#define MODE(m)  ((mode & 0x07) == CIPHER_MODE_##m)
#define SUITE(s) ((mode & 0x08) == CIPHER_SUITE_##s)
#define ALGO(a)  ((mode & 0x10) == CIPHER_ALGO_##a)

#define GET_ALGO void (*blockCrypt)(const uint8_t KEY[8], const uint8_t in[8], uint8_t out[8], bool inverse) =\
	ALGO(AES) ? AES :\
		DES
void Crypt(uint8_t* out, const uint8_t* in, uint32_t len, uint8_t mode, const uint8_t* KEY, const uint8_t* IV)
{
	if (SUITE(EDE))
	{
		Crypt  (out, in,  len, mode ^ CIPHER_SUITE_EDE, KEY +  0, IV);
		Decrypt(out, out, len, mode ^ CIPHER_SUITE_EDE, KEY +  8, IV);
		Crypt  (out, out, len, mode ^ CIPHER_SUITE_EDE, KEY + 16, IV);
		return;
	}

	GET_ALGO;

	uint8_t I[8];
	uint8_t O[8];
	if (MODE(CBC) || MODE(PCBC))
		memcpy(O, IV, 8);
	else if (MODE(CFB) || MODE(OFB) || MODE(CTR))
		memcpy(I, IV, 8);
	uint32_t i = 0;
	while (i+7 < len)
	{
		if (MODE(ECB))
			memcpy(I, in + i, 8);
		else if (MODE(CBC) || MODE(PCBC))
			for (uint8_t j = 0; j < 8; j++)
				I[j] = in[i+j] ^ O[j];

		blockCrypt(KEY, I, O, false);

		if (MODE(CFB))
			for (uint8_t j = 0; j < 8; j++)
			{
				O[j] ^= in[i+j];
				I[j] = O[j];
			}
		else if (MODE(OFB))
			for (uint8_t j = 0; j < 8; j++)
			{
				I[j] = O[j];
				O[j] ^= in[i+j];
			}

		memcpy(out + i, O, 8);
		if (MODE(PCBC))
			for (uint8_t j = 0; j < 8; j++)
				O[j] ^= in[i+j];
		else if (MODE(CTR))
		{
			for (uint8_t j = 0; j < 8; j++)
				out[i+j] ^= in[i+j];
			I[7]++;
			if (!I[7]) I[6]++;
			if (!I[6]) I[5]++;
			if (!I[5]) I[4]++;
			if (!I[4]) I[3]++;
			if (!I[3]) I[2]++;
			if (!I[2]) I[1]++;
			if (!I[1]) I[0]++;
		}

		i += 8;
	}
	uint8_t remaining = len % 8;
	if (remaining)
	{
		if (MODE(ECB))
		{
			memcpy(I, in + i, remaining);
			memset(I + remaining, 0, 8-remaining);
		}
		else if (MODE(CBC) || MODE(PCBC))
			for (uint8_t j = 0; j < 8; j++)
				I[j] = (j < remaining ? in[i+j] : 0) ^ O[j];

		blockCrypt(KEY, I, out + i, false);

		if (MODE(CFB) || MODE(OFB) || MODE(CTR))
			for (uint8_t j = 0; j < 8; j++)
				out[i+j] ^= in[i+j];
	}
}

void Decrypt(uint8_t* out, const uint8_t* in, uint32_t len, uint8_t mode, const uint8_t* KEY, const uint8_t* IV)
{
	if (len % 8)
		return;

	GET_ALGO;

	if (SUITE(EDE))
	{
		Decrypt(out, in,  len, mode ^ CIPHER_SUITE_EDE, KEY +  0, IV);
		Crypt  (out, out, len, mode ^ CIPHER_SUITE_EDE, KEY +  8, IV);
		Decrypt(out, out, len, mode ^ CIPHER_SUITE_EDE, KEY + 16, IV);
		return;
	}

	uint8_t I[8];
	if (MODE(CBC) || MODE(PCBC) || MODE(CFB) || MODE(OFB) || MODE(CTR))
		memcpy(I, IV, 8);
	for (uint32_t i = 0; i < len; i+=8)
	{
		if (MODE(CFB))
		{
			blockCrypt(KEY, I, out + i, false);
			for (uint8_t j = 0; j < 8; j++)
				out[i+j] ^= in[i+j];
			memcpy(I, in + i, 8);
		}
		else if (MODE(OFB))
		{
			blockCrypt(KEY, I, out + i, false);
			memcpy(I, out + i, 8);
			for (uint8_t j = 0; j < 8; j++)
				out[i+j] ^= in[i+j];
		}
		else if (MODE(CTR))
		{
			blockCrypt(KEY, I, out + i, false);
			for (uint8_t j = 0; j < 8; j++)
				out[i+j] ^= in[i+j];
			I[7]++;
			if (!I[7]) I[6]++;
			if (!I[6]) I[5]++;
			if (!I[5]) I[4]++;
			if (!I[4]) I[3]++;
			if (!I[3]) I[2]++;
			if (!I[2]) I[1]++;
			if (!I[1]) I[0]++;
		}
		else
		{
			blockCrypt(KEY, in + i, out + i, true);
			if (MODE(CBC))
			{
				for (uint8_t j = 0; j < 8; j++)
					out[i+j] ^= I[j];
				memcpy(I, in + i, 8);
			}
			else if (MODE(PCBC))
				for (uint8_t j = 0; j < 8; j++)
				{
					out[i+j] ^= I[j];
					I[j] = in[i+j] ^ out[i+j];
				}
		}
	}
}
