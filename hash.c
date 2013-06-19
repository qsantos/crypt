#include "hash.h"

#include <string.h>

uint8_t HashBlockSize(uint8_t mode)
{
	switch (mode & 0x07)
	{
		case HASH_MD2:
			return 16;
		case HASH_MD4:
		case HASH_MD5:
		case HASH_SHA1:
		case HASH_SHA256:
		case HASH_SHA224:
			return 64;
		case HASH_SHA512:
		case HASH_SHA384:
			return 128;
		default:
			return 0;
	}
}

uint8_t DigestLength(uint8_t mode)
{
	switch (mode & 0x07)
	{
	case HASH_MD2:
	case HASH_MD4:
	case HASH_MD5:
		return 16;
	case HASH_SHA1:
		return 20;
	case HASH_SHA256:
		return 32;
	case HASH_SHA224:
		return 28;
	case HASH_SHA512:
		return 64;
	case HASH_SHA384:
		return 48;
	default:
		return 1;
	}
}

int8_t HashFunCode(char* fun)
{
	if (!strcmp(fun, "md2"))
		return HASH_MD2;
	else if (!strcmp(fun, "md4"))
		return HASH_MD4;
	else if (!strcmp(fun, "md5"))
		return HASH_MD5;
	else if (!strcmp(fun, "sha1"))
		return HASH_SHA1;
	else if (!strcmp(fun, "sha256"))
		return HASH_SHA256;
	else if (!strcmp(fun, "sha224"))
		return HASH_SHA224;
	else if (!strcmp(fun, "sha512"))
		return HASH_SHA512;
	else if (!strcmp(fun, "sha384"))
		return HASH_SHA384;
	else
		return -1;
}

#define CASE1(F, G)           \
case HASH_##F:                \
	F##G((F##_CTX*) ctx); \
	break;
#define CASEX(F, G, ...)                   \
case HASH_##F:                             \
	F##G((F##_CTX*) ctx, __VA_ARGS__); \
	break;
void HashInit(uint8_t mode, Hash_CTX* ctx)
{
	switch (mode)
	{
	CASE1(MD2,    Init);
	CASE1(MD4,    Init);
	CASE1(MD5,    Init);
	CASE1(SHA1,   Init);
	CASE1(SHA256, Init);
	CASE1(SHA224, Init);
	CASE1(SHA512, Init);
	CASE1(SHA384, Init);
	default:
		break;
	}
}

typedef struct
{
	uint64_t len;
	uint8_t  bufLen;
	uint8_t  buffer[64];
} Any_CTX;

void HashBlock(uint8_t mode, Any_CTX* ctx, const uint8_t* data)
{
	switch (mode)
	{
	CASEX(MD2,    Block, data);
	CASEX(MD4,    Block, data);
	CASEX(MD5,    Block, data);
	CASEX(SHA1,   Block, data);
	CASEX(SHA256, Block, data);
	CASEX(SHA224, Block, data);
	CASEX(SHA512, Block, data);
	CASEX(SHA384, Block, data);
	default:
		break;
	}
}

void HashUpdate(uint8_t mode, Hash_CTX* _ctx, const uint8_t* data, uint64_t len)
{
	Any_CTX* ctx = (Any_CTX*) _ctx;
	uint8_t blockSize = HashBlockSize(mode);
	if (blockSize == 0)
		return;

	uint32_t i = 0;
	uint8_t availBuf = blockSize - ctx->bufLen;
	if (len >= availBuf)
	{
		memcpy(ctx->buffer + ctx->bufLen, data, availBuf);
		HashBlock(mode, ctx, ctx->buffer);
		i = availBuf;
		ctx->bufLen = 0;

		uint8_t last = len - blockSize;
		while (i <= last)
		{
			HashBlock(mode, ctx, data + i);
			i+= blockSize;
		}
	}
	memcpy(ctx->buffer + ctx->bufLen, data + i, len - i);
	ctx->bufLen += len - i;
	ctx->len += len;
}

void HashFinal(uint8_t mode, Hash_CTX* ctx, uint8_t* dst)
{
	switch (mode)
	{
	CASEX(MD2,    Final, dst);
	CASEX(MD4,    Final, dst);
	CASEX(MD5,    Final, dst);
	CASEX(SHA1,   Final, dst);
	CASEX(SHA256, Final, dst);
	CASEX(SHA224, Final, dst);
	CASEX(SHA512, Final, dst);
	CASEX(SHA384, Final, dst);
	default:
		break;
	}
}

void Hash(uint8_t mode, uint8_t* digest, const uint8_t* data, uint64_t len)
{
	Hash_CTX ctx;
	HashInit  (mode, &ctx);
	HashUpdate(mode, &ctx, data, len);
	HashFinal (mode, &ctx, digest);
}