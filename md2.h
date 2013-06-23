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

#ifndef MD2_H
#define MD2_H

// MD2 provides a 16 byte hash
#include <stdbool.h>
#include <stdint.h>

typedef struct
{
	uint64_t len;
	uint8_t  bufLen;
	uint8_t  buffer[16];
	uint8_t  C[16];
	uint8_t  X[16];
} MD2_CTX;

void MD2Init  (MD2_CTX* md2);
void MD2Block (MD2_CTX* md2, const uint8_t block[16]);
void MD2Update(MD2_CTX* md2, const uint8_t* data, uint64_t len);
void MD2Final (MD2_CTX* md2, uint8_t dst[16]);

void MD2(uint8_t dst[16], const uint8_t* src, uint64_t slen);

#endif
