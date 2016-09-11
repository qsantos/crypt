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

#ifndef MD4_H
#define MD4_H

// MD3 provides a 16 byte hash
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t total_length;
    size_t bytes_in_buffer;
    uint8_t buffer[64];
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
} MD4Context;

void md4_init(MD4Context* ctx);
void md4_block(MD4Context* ctx, const uint8_t block[64]);
void md4_update(MD4Context* ctx, const uint8_t* data, size_t length);
void md4_final(MD4Context* ctx, uint8_t dst[16]);

void md4(uint8_t dst[16], const uint8_t* src, size_t length);

#endif
