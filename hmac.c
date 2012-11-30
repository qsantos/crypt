// Reference:
// RFC 2104
#include "hmac.h"

#include <string.h>

#include "hash.h"

#define B 64

void HMAC(uint8_t mode, uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t* digest)
{
	Hash_CTX ctx;
	uint8_t ipad[B]; memset(ipad, 0, B);
	uint8_t opad[B]; memset(opad, 0, B);

	if (klen > B)
	{
		HashInit  (mode, &ctx);
		HashUpdate(mode, &ctx, key, klen);
		HashFinal (mode, &ctx, ipad);
		memcpy(opad, ipad, 16);
	}
	else
	{
		memcpy(ipad, key, klen);
		memcpy(opad, key, klen);
	}

	for (uint8_t i = 0; i < B; i++)
	{
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	HashInit  (mode, &ctx);
	HashUpdate(mode, &ctx, ipad, B);
	HashUpdate(mode, &ctx, text, tlen);
	HashFinal (mode, &ctx, digest);

	HashInit  (mode, &ctx);
	HashUpdate(mode, &ctx, opad, B);
	HashUpdate(mode, &ctx, digest, 16);
	HashFinal (mode, &ctx, digest);
}

#define HMAC_HASH(F)                                                                      \
void HMAC_##F(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t* digest) \
{                                                                                         \
	HMAC(HASH_##F, text, tlen, key, klen, digest);                                    \
}

HMAC_HASH(MD2)
HMAC_HASH(MD4)
HMAC_HASH(MD5)
HMAC_HASH(SHA1)
HMAC_HASH(SHA256)
HMAC_HASH(SHA224)
HMAC_HASH(SHA512)
HMAC_HASH(SHA384)
