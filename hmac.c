// Reference:
// RFC 2104
#include "hmac.h"

#include <string.h>

#include "md5.h"

#define B 64
#define L 16

void HMAC(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[16])
{
	MD5_CTX md5;
	uint8_t ipad[B]; memset(ipad, 0, B);
	uint8_t opad[B]; memset(opad, 0, B);

	if (klen > B)
	{
		MD5Init  (&md5);
		MD5Update(&md5, key, klen);
		MD5Final (&md5, ipad);
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

	MD5Init  (&md5);
	MD5Update(&md5, ipad, B);
	MD5Update(&md5, text, tlen);
	MD5Final (&md5, digest);

	MD5Init  (&md5);
	MD5Update(&md5, opad, B);
	MD5Update(&md5, digest, 16);
	MD5Final (&md5, digest);
}
