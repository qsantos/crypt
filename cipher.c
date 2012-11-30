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

uint8_t BlockSize(uint8_t mode)
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
	ctx->blocksize = BlockSize(mode);
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
		for (int8_t i = ctx->blocksize-1; i >= 0; i--)
			if (carry)
				carry = ++ctx->feedback[i] != 0;
		break;
	default:
		break;
	}
}

uint32_t CipherUpdate(Cipher_CTX* ctx, uint8_t* out, const uint8_t* in, uint32_t len, bool inverse)
{
	uint8_t availBuf = ctx->blocksize - ctx->bufLen;
	uint32_t remain  = len;
	if (remain >= availBuf)
	{
		memcpy(ctx->buffer + ctx->bufLen, in, availBuf);
		CipherBlock(ctx, out, ctx->buffer, inverse);
		in     += availBuf;
		out    += ctx->blocksize;
		remain -= availBuf;

		while (remain >= ctx->blocksize)
		{
			CipherBlock(ctx, out, in, inverse);
			remain -= ctx->blocksize;
			in     += ctx->blocksize;
			out    += ctx->blocksize;
		}

		memcpy(ctx->buffer, in, remain);
		ctx->bufLen += remain;
		return availBuf + len;
	}
	else
	{
		memcpy(ctx->buffer + ctx->bufLen, in, len);
		ctx->bufLen += len;
		return 0;
	}
}

uint32_t CipherFinal(Cipher_CTX* ctx, uint8_t* out, bool inverse)
{
	if (!ctx->bufLen)
		return 0;

	memset(ctx->buffer + ctx->bufLen, 0, ctx->blocksize - ctx->bufLen);
	CipherBlock(ctx, out, ctx->buffer, inverse);
	return ctx->blocksize;
}

uint32_t Cipher(uint8_t* out, const uint8_t* in, uint32_t len, uint8_t mode, const uint8_t* key, const uint8_t* IV, bool inverse)
{
	Cipher_CTX ctx;
	CipherInit(&ctx, mode, key, IV);
	uint32_t ret = CipherUpdate(&ctx, out, in, len, inverse);
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

uint32_t EncryptUpdate(Encrypt_CTX* ctx, uint8_t* out, const uint8_t* in, uint32_t len)
{
	return CipherUpdate(ctx, out, in, len, false);
}

uint32_t EncryptFinal(Encrypt_CTX* ctx, uint8_t* out)
{
	return CipherFinal(ctx, out, false);
}

uint32_t Encrypt(uint8_t* o, const uint8_t* i, uint32_t l, uint8_t m, const uint8_t* k, const uint8_t* IV)
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

uint32_t DecryptUpdate(Decrypt_CTX* ctx, uint8_t* out, const uint8_t* in, uint32_t len)
{
	return CipherUpdate(ctx, out, in, len, true);
}

uint32_t DecryptFinal(Decrypt_CTX* ctx, uint8_t* out)
{
	return CipherFinal(ctx, out, true);
}

uint32_t Decrypt(uint8_t* o, const uint8_t* i, uint32_t l, uint8_t m, const uint8_t* k, const uint8_t* IV)
{
	return Cipher(o, i, l, m, k, IV, true);
}
