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

uint8_t HashBlockSize(uint8_t mode);
uint8_t DigestLength (uint8_t mode);
int8_t  HashFunCode  (char*   fun);

void HashInit  (uint8_t mode, Hash_CTX* ctx);
void HashUpdate(uint8_t mode, Hash_CTX* ctx, const uint8_t* data, uint64_t len);
void HashFinal (uint8_t mode, Hash_CTX* ctx, uint8_t* dst);

void Hash(uint8_t mode, uint8_t* digest, const uint8_t* data, uint64_t len);

#endif
