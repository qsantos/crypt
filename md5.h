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

#ifndef MD5_H
#define MD5_H

// md5 provides a 16 byte hash
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
} MD5Context;

void md5_init(MD5Context* ctx);
void md5_block(MD5Context* ctx, const uint8_t block[64]);
void md5_update(MD5Context* ctx, const uint8_t* data, size_t length);
void md5_final(MD5Context* ctx, uint8_t dst[16]);

void md5(uint8_t dst[16], const uint8_t* src, size_t length);

#endif
