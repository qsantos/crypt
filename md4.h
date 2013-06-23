/*\
 *  This is an awesome programm simulating awesome battles of awesome robot tanks
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

#ifndef MD4_H
#define MD4_H

// MD3 provides a 16 byte hash
#include <stdint.h>

typedef struct
{
	uint64_t len;
	uint8_t  bufLen;
	uint8_t  buffer[64];
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
} MD4_CTX;

void MD4Init  (MD4_CTX* md4);
void MD4Block (MD4_CTX* md4, const uint8_t block[64]);
void MD4Update(MD4_CTX* md4, const uint8_t* data, uint64_t len);
void MD4Final (MD4_CTX* md4, uint8_t dst[16]);

void MD4(uint8_t dst[16], const uint8_t* src, uint64_t slen);

#endif
