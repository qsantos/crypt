#include "cipher.h"

#include <string.h>

#include "des.h"
#include "rijndael.h"

#define ENC(a)   ((mode & 0x03) == CIPHER_##a)
#define MODE(m)  ((mode & 0x70) == CIPHER_MODE_##m)
#define CHAIN(s) ((mode & 0x80) == CIPHER_CHAIN_##s)

#define GET_ENC void (*blockCrypt)(const uint8_t* KEY, const uint8_t* in, uint8_t* out, bool inverse) =\
	ENC(RIJNDAEL256) ? Rijndael256 :\
	ENC(RIJNDAEL192) ? Rijndael192 :\
	ENC(RIJNDAEL128) ? Rijndael128 :\
	                   DES

uint8_t KeyLength(uint8_t mode)
{
	switch (mode & 0x03)
	{
	case CIPHER_DES:
	case CIPHER_RIJNDAEL128:
		return 16;
	case CIPHER_RIJNDAEL192:
		return 24;
	case CIPHER_RIJNDAEL256:
		return 32;
	default:
		return 0;
	}
}

int8_t CipherFunCode(char* fun)
{
	if (!strcmp(fun, "des"))
		return CIPHER_DES;
	else if (!strcmp(fun, "aes128"))
		return CIPHER_AES128;
	else if (!strcmp(fun, "aes192"))
		return CIPHER_AES192;
	else if (!strcmp(fun, "aes256"))
		return CIPHER_AES256;
	else
		return -1;
}

void Crypt(uint8_t* out, const uint8_t* in, uint32_t len, uint8_t mode, const uint8_t* KEY, const uint8_t* IV)
{
	if (CHAIN(EDE))
	{
		Crypt  (out, in,  len, mode ^ CIPHER_CHAIN_EDE, KEY +  0, IV);
		Decrypt(out, out, len, mode ^ CIPHER_CHAIN_EDE, KEY +  8, IV);
		Crypt  (out, out, len, mode ^ CIPHER_CHAIN_EDE, KEY + 16, IV);
		return;
	}

	GET_ENC;

	uint8_t I[32];
	uint8_t O[32];
	uint8_t size = KeyLength(mode);
	if (size == 0)
		return;

	if (MODE(CBC) || MODE(PCBC))
		memcpy(O, IV, size);
	else if (MODE(CFB) || MODE(OFB) || MODE(CTR))
		memcpy(I, IV, size);
	uint32_t i = 0;
	while (i+size-1 < len)
	{
		if (MODE(ECB))
			memcpy(I, in + i, size);
		else if (MODE(CBC) || MODE(PCBC))
			for (uint8_t j = 0; j < size; j++)
				I[j] = in[i+j] ^ O[j];

		blockCrypt(KEY, I, O, false);

		if (MODE(CFB))
			for (uint8_t j = 0; j < size; j++)
			{
				O[j] ^= in[i+j];
				I[j] = O[j];
			}
		else if (MODE(OFB))
			for (uint8_t j = 0; j < size; j++)
			{
				I[j] = O[j];
				O[j] ^= in[i+j];
			}

		memcpy(out + i, O, size);
		if (MODE(PCBC))
			for (uint8_t j = 0; j < size; j++)
				O[j] ^= in[i+j];
		else if (MODE(CTR))
		{
			for (uint8_t j = 0; j < size; j++)
				out[i+j] ^= in[i+j];
			I[size-1]++;
			for (int i = size-2; i >= 0; i--)
				if (!I[i+1])
					I[i]++;
		}

		i += size;
	}
	uint8_t remaining = len % size;
	if (remaining)
	{
		if (MODE(ECB))
		{
			memcpy(I, in + i, remaining);
			memset(I + remaining, 0, size-remaining);
		}
		else if (MODE(CBC) || MODE(PCBC))
			for (uint8_t j = 0; j < size; j++)
				I[j] = (j < remaining ? in[i+j] : 0) ^ O[j];

		blockCrypt(KEY, I, out + i, false);

		if (MODE(CFB) || MODE(OFB) || MODE(CTR))
			for (uint8_t j = 0; j < size; j++)
				out[i+j] ^= in[i+j];
	}
}

void Decrypt(uint8_t* out, const uint8_t* in, uint32_t len, uint8_t mode, const uint8_t* KEY, const uint8_t* IV)
{
	uint8_t size = KeyLength(mode);
	if (size == 0)
		return;

	if (len % size)
		return;

	GET_ENC;

	if (CHAIN(EDE))
	{
		Decrypt(out, in,  len, mode ^ CIPHER_CHAIN_EDE, KEY +  0, IV);
		Crypt  (out, out, len, mode ^ CIPHER_CHAIN_EDE, KEY +  8, IV);
		Decrypt(out, out, len, mode ^ CIPHER_CHAIN_EDE, KEY + 16, IV);
		return;
	}

	uint8_t I[32];
	if (MODE(CBC) || MODE(PCBC) || MODE(CFB) || MODE(OFB) || MODE(CTR))
		memcpy(I, IV, size);
	for (uint32_t i = 0; i < len; i += size)
	{
		if (MODE(CFB))
		{
			blockCrypt(KEY, I, out + i, false);
			for (uint8_t j = 0; j < size; j++)
				out[i+j] ^= in[i+j];
			memcpy(I, in + i, size);
		}
		else if (MODE(OFB))
		{
			blockCrypt(KEY, I, out + i, false);
			memcpy(I, out + i, size);
			for (uint8_t j = 0; j < size; j++)
				out[i+j] ^= in[i+j];
		}
		else if (MODE(CTR))
		{
			blockCrypt(KEY, I, out + i, false);
			for (uint8_t j = 0; j < size; j++)
				out[i+j] ^= in[i+j];
			I[size-1]++;
			for (int i = size-2; i >= 0; i--)
				if (!I[i+1])
					I[i]++;
		}
		else
		{
			blockCrypt(KEY, in + i, out + i, true);
			if (MODE(CBC))
			{
				for (uint8_t j = 0; j < size; j++)
					out[i+j] ^= I[j];
				memcpy(I, in + i, size);
			}
			else if (MODE(PCBC))
				for (uint8_t j = 0; j < size; j++)
				{
					out[i+j] ^= I[j];
					I[j] = in[i+j] ^ out[i+j];
				}
		}
	}
}
