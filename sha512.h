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

#ifndef SHA512_h
#define SHA512_h

// SHA-2: SHA-384/SHA-512
// SHA512 provides a 64 byte hash
// SHA384 provides a 48 byte hash
#include <stdint.h>

typedef struct
{
	uint64_t len; // TODO
	uint8_t  bufLen;
	uint8_t  buffer[128];
	uint64_t H[8];
} SHA512_CTX;

void SHA512Init  (SHA512_CTX* sha512);
void SHA512Block (SHA512_CTX* sha512, const uint8_t block[128]);
void SHA512Update(SHA512_CTX* sha512, const uint8_t* data, uint64_t len);
void SHA512Final (SHA512_CTX* sha512, uint8_t dst[64]);

void SHA512(uint8_t dst[64], const uint8_t* src, uint64_t slen);



typedef SHA512_CTX SHA384_CTX;

void SHA384Init  (SHA384_CTX* sha384);
void SHA384Block (SHA384_CTX* sha384, const uint8_t block[128]);
void SHA384Update(SHA384_CTX* sha384, const uint8_t* data, uint64_t len);
void SHA384Final (SHA384_CTX* sha384, uint8_t dst[48]);

void SHA384(uint8_t dst[48], const uint8_t* src, uint64_t slen);

#endif
