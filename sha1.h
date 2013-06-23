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

#ifndef SHA1_H
#define SHA1_H

// SHA1 provides a 20 byte hash
#include <stdint.h>

typedef struct
{
	uint64_t len;
	uint8_t  bufLen;
	uint8_t  buffer[64];
	uint32_t H[5];
} SHA1_CTX;

void SHA1Init  (SHA1_CTX* sha1);
void SHA1Block (SHA1_CTX* sha1, const uint8_t block[64]);
void SHA1Update(SHA1_CTX* sha1, const uint8_t* data, uint64_t len);
void SHA1Final (SHA1_CTX* sha1, uint8_t dst[20]);

void SHA1(uint8_t dst[20], const uint8_t* src, uint64_t slen);

#endif
