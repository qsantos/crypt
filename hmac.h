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

#ifndef HMAC_H
#define HMAC_h

#include <stddef.h>
#include <stdint.h>

void HMAC(uint8_t mode, uint8_t* text, uint64_t tlen, uint8_t* key, size_t klen, uint8_t* digest);

void HMAC_MD2   (uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[16]);
void HMAC_MD4   (uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[16]);
void HMAC_MD5   (uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[16]);
void HMAC_SHA1  (uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[20]);
void HMAC_SHA256(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[32]);
void HMAC_SHA224(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[28]);
void HMAC_SHA512(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[64]);
void HMAC_SHA384(uint8_t* text, uint64_t tlen, uint8_t* key, uint64_t klen, uint8_t digest[48]);

#endif
