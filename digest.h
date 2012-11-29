#ifndef DIGEST_H
#define DIGEST_H

#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

#define HASH_MD2    0x00
#define HASH_MD4    0x01
#define HASH_MD5    0x02
#define HASH_SHA1   0x03
#define HASH_SHA256 0x04
#define HASH_SHA224 0x05
#define HASH_SHA512 0x06
#define HASH_SHA384 0x07

typedef union
{
	MD2_CTX    md2;
	MD4_CTX    md4;
	MD5_CTX    md5;
	SHA1_CTX   sha1;
	SHA256_CTX sha256;
	SHA224_CTX sha224;
	SHA512_CTX sha512;
	SHA384_CTX sha384;
} Hash_CTX;

uint8_t DigestLength(uint8_t mode);
int8_t  HashFunCode (char*   fun);

void HashInit  (uint8_t mode, Hash_CTX* ctx);
void HashUpdate(uint8_t mode, Hash_CTX* ctx, const uint8_t* data, uint64_t len);
void HashFinal (uint8_t mode, Hash_CTX* ctx, uint8_t* dst);

#endif
