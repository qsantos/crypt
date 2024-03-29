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

// sha1 provides a 20 byte hash
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t total_length;
    size_t bytes_in_buffer;
    uint8_t buffer[64];
    uint32_t H[5];
    uint8_t dummy[4];
} SHA1Context;

void sha1_init(SHA1Context* ctx);
void sha1_block(SHA1Context* ctx, const uint8_t block[64]);
void sha1_update(SHA1Context* ctx, const uint8_t* data, size_t length);
void sha1_final(SHA1Context* ctx, uint8_t dst[20]);

void sha1(uint8_t dst[20], const uint8_t* src, size_t length);

#endif
