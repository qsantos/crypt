#include "digest.h"

#include <string.h>

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

int8_t HashFunCode (char* fun)
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
void HashInit(uint8_t mode, Context* ctx)
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

void HashUpdate(uint8_t mode, Context* ctx, const uint8_t* data, uint64_t len)
{
	switch (mode)
	{
	CASEX(MD2,    Update, data, len);
	CASEX(MD4,    Update, data, len);
	CASEX(MD5,    Update, data, len);
	CASEX(SHA1,   Update, data, len);
	CASEX(SHA256, Update, data, len);
	CASEX(SHA224, Update, data, len);
	CASEX(SHA512, Update, data, len);
	CASEX(SHA384, Update, data, len);
	default:
		break;
	}
}

void HashFinal (uint8_t mode, Context* ctx, uint8_t* dst)
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
