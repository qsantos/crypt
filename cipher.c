/*\
 *  Insecure implementation of some cryptographic primitives
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

#include "cipher.h"

#include <string.h>

#include "des.h"
#include "rijndael.h"

#define ENC(a)   ((mode & 0x03) == CIPHER_##a)
#define GET_ENC void (*blockCrypt)(const uint8_t* key, const uint8_t* in, uint8_t* out, bool inverse) =\
	ENC(RIJNDAEL256) ? Rijndael256 :\
	ENC(RIJNDAEL192) ? Rijndael192 :\
	ENC(RIJNDAEL128) ? Rijndael128 :\
	                   DES

uint8_t KeyLength(uint8_t mode)
{
	switch (mode & 0x03)
	{
	case CIPHER_DES:
		return 7;
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

uint8_t CipherBlockSize(uint8_t mode)
{
	switch (mode & 0x03)
	{
	case CIPHER_DES:
		return 8;
	case CIPHER_RIJNDAEL128:
	case CIPHER_RIJNDAEL192:
	case CIPHER_RIJNDAEL256:
		return 16;
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

void CipherInit(Cipher_CTX* ctx, uint8_t mode, const uint8_t* key, const uint8_t* IV)
{
	memset(ctx, 0, sizeof(Cipher_CTX));
	memcpy(ctx->key, key, KeyLength(mode));
	ctx->mode      = mode;
	ctx->blocksize = CipherBlockSize(mode);
	if (IV)
		memcpy(ctx->feedback, IV, ctx->blocksize);
}

void CipherBlock(Cipher_CTX* ctx, uint8_t* out, const uint8_t* in, bool inverse)
{
	uint8_t mode = ctx->mode;
	GET_ENC;

	uint8_t O[16];
	switch (mode & 0x70)
	{
	case CIPHER_MODE_ECB:
		blockCrypt(ctx->key, in, out, inverse);
		break;
	case CIPHER_MODE_CBC:
		if (inverse)
		{
			blockCrypt(ctx->key, in, out, inverse);
			for (uint8_t i = 0; i < ctx->blocksize; i++)
				out[i] ^= ctx->feedback[i];
			memcpy(ctx->feedback, in, ctx->blocksize);
		}
		else
		{
			for (uint8_t i = 0; i < ctx->blocksize; i++)
				ctx->feedback[i] ^= in[i];
			blockCrypt(ctx->key, ctx->feedback, out, inverse);
			memcpy(ctx->feedback, out, ctx->blocksize);
		}
		break;
	case CIPHER_MODE_PCBC:
		if (inverse)
		{
			blockCrypt(ctx->key, in, out, inverse);
			for (uint8_t i = 0; i < ctx->blocksize; i++)
				out[i] ^= ctx->feedback[i];
		}
		else
		{
			for (uint8_t i = 0; i < ctx->blocksize; i++)
				ctx->feedback[i] ^= in[i];
			blockCrypt(ctx->key, ctx->feedback, out, inverse);
		}
		memcpy(ctx->feedback, out, ctx->blocksize);
		for (uint8_t i = 0; i < ctx->blocksize; i++)
			ctx->feedback[i] ^= in[i];
		break;
	case CIPHER_MODE_CFB:
		blockCrypt(ctx->key, ctx->feedback, O, true);
		for (uint8_t i = 0; i < ctx->blocksize; i++)
			out[i] = in[i] ^ O[i];
		memcpy(ctx->feedback, inverse ? out : in, ctx->blocksize);
		break;
	case CIPHER_MODE_OFB:
		blockCrypt(ctx->key, ctx->feedback, O, true);
		for (uint8_t i = 0; i < ctx->blocksize; i++)
			out[i] = in[i] ^ O[i];
		memcpy(ctx->feedback, O, ctx->blocksize);
		break;
	case CIPHER_MODE_CTR:
		blockCrypt(ctx->key, ctx->feedback, out, true);
		for (uint8_t i = 0; i < ctx->blocksize; i++)
			out[i] ^= in[i];
		bool carry = true;
		for (size_t i = ctx->blocksize; i --> 0; )
			if (carry)
				carry = ++ctx->feedback[i] != 0;
		break;
	default:
		break;
	}
}

size_t CipherUpdate(Cipher_CTX* ctx, uint8_t* out, const uint8_t* in, size_t len, bool inverse)
{
	size_t availBuf = ctx->blocksize - ctx->bufLen;
	size_t remain   = len;
	if (remain >= availBuf)
	{
		memcpy(ctx->buffer + ctx->bufLen, in, availBuf);
		CipherBlock(ctx, out, ctx->buffer, inverse);
		remain -= availBuf;
		in     += availBuf;
		out    += ctx->blocksize;

		while (remain >= ctx->blocksize)
		{
			CipherBlock(ctx, out, in, inverse);
			remain -= ctx->blocksize;
			in     += ctx->blocksize;
			out    += ctx->blocksize;
		}

		size_t r = len + ctx->bufLen - remain;
		memcpy(ctx->buffer, in, remain);
		ctx->bufLen = remain;
		return r;
	}
	else
	{
		memcpy(ctx->buffer + ctx->bufLen, in, len);
		ctx->bufLen += len;
		return 0;
	}
}

size_t CipherFinal(Cipher_CTX* ctx, uint8_t* out, bool inverse)
{
	if (!ctx->bufLen)
		return 0;

	memset(ctx->buffer + ctx->bufLen, 0, ctx->blocksize - ctx->bufLen);
	CipherBlock(ctx, out, ctx->buffer, inverse);
	return ctx->blocksize;
}

size_t Cipher(uint8_t* out, const uint8_t* in, uint32_t len, uint8_t mode, const uint8_t* key, const uint8_t* IV, bool inverse)
{
	Cipher_CTX ctx;
	CipherInit(&ctx, mode, key, IV);
	size_t ret = CipherUpdate(&ctx, out, in, len, inverse);
	ret += CipherFinal(&ctx, out, inverse);
	return ret;
}

void EncryptInit(Encrypt_CTX* ctx, uint8_t mode, const uint8_t* key, const uint8_t* IV)
{
	CipherInit(ctx, mode, key, IV);
}

void EncryptBlock(Encrypt_CTX* ctx, uint8_t* out, const uint8_t* in)
{
	CipherBlock(ctx, out, in, false);
}

size_t EncryptUpdate(Encrypt_CTX* ctx, uint8_t* out, const uint8_t* in, uint32_t len)
{
	return CipherUpdate(ctx, out, in, len, false);
}

size_t EncryptFinal(Encrypt_CTX* ctx, uint8_t* out)
{
	return CipherFinal(ctx, out, false);
}

size_t Encrypt(uint8_t* o, const uint8_t* i, uint32_t l, uint8_t m, const uint8_t* k, const uint8_t* IV)
{
	return Cipher(o, i, l, m, k, IV, true);
}

void DecryptInit(Decrypt_CTX* ctx, uint8_t mode, const uint8_t* key, const uint8_t* IV)
{
	CipherInit(ctx, mode, key, IV);
}

void DecryptBlock(Decrypt_CTX* ctx, uint8_t* out, const uint8_t* in)
{
	CipherBlock(ctx, out, in, true);
}

size_t DecryptUpdate(Decrypt_CTX* ctx, uint8_t* out, const uint8_t* in, uint32_t len)
{
	return CipherUpdate(ctx, out, in, len, true);
}

size_t DecryptFinal(Decrypt_CTX* ctx, uint8_t* out)
{
	return CipherFinal(ctx, out, true);
}

size_t Decrypt(uint8_t* o, const uint8_t* i, uint32_t l, uint8_t m, const uint8_t* k, const uint8_t* IV)
{
	return Cipher(o, i, l, m, k, IV, true);
}
