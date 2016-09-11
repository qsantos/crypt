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

#ifndef SHA256_H
#define SHA256_H

// SHA-2: SHA-224/SHA-256
// SHA256 provides a 32 byte hash
// SHA224 provides a 28 byte hash
#include <stddef.h>
#include <stdint.h>

typedef struct
{
	size_t   len;
	size_t   bufLen;
	uint8_t  buffer[64];
	uint32_t H[8];
} SHA256_CTX;

void SHA256Init  (SHA256_CTX* sha256);
void SHA256Block (SHA256_CTX* sha256, const uint8_t block[64]);
void SHA256Update(SHA256_CTX* sha256, const uint8_t* data, size_t len);
void SHA256Final (SHA256_CTX* sha256, uint8_t dst[32]);

void SHA256(uint8_t dst[32], const uint8_t* src, size_t slen);



typedef SHA256_CTX SHA224_CTX;

void SHA224Init  (SHA224_CTX* sha224);
void SHA224Block (SHA224_CTX* sha224, const uint8_t block[64]);
void SHA224Update(SHA224_CTX* sha224, const uint8_t* data, size_t len);
void SHA224Final (SHA224_CTX* sha224, uint8_t dst[28]);

void SHA224(uint8_t dst[28], const uint8_t* src, size_t slen);

#endif
