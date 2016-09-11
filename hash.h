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

typedef union {
    MD2Context md2_ctx;
    MD4Context md4_ctx;
    MD5Context md5_ctx;
    SHA1Context sha1_ctx;
    SHA256Context sha256_ctx;
    SHA224Context sha224_ctx;
    SHA512Context sha512_ctx;
    SHA384Context sha384_ctx;
} HashContext;

uint8_t hash_blocksize(uint8_t mode);
uint8_t digest_length(uint8_t mode);
int8_t hash_function_code(char* function);

void hash_init(uint8_t mode, HashContext* ctx);
void hash_update(uint8_t mode, HashContext* ctx, const uint8_t* data, uint64_t length);
void hash_final(uint8_t mode, HashContext* ctx, uint8_t* dst);

void hash(uint8_t mode, uint8_t* digest, const uint8_t* data, uint64_t length);

#endif
