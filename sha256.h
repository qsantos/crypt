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
// sha256 provides a 32 byte hash
// sha224 provides a 28 byte hash
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t total_length;
    size_t bytes_in_buffer;
    uint8_t buffer[64];
    uint32_t H[8];
} SHA256Context;

void sha256_init(SHA256Context* ctx);
void sha256_block(SHA256Context* ctx, const uint8_t block[64]);
void sha256_udpate(SHA256Context* ctx, const uint8_t* data, size_t length);
void sha256_final(SHA256Context* ctx, uint8_t dst[32]);

void sha256(uint8_t dst[32], const uint8_t* src, size_t length);


typedef SHA256Context SHA224Context;

void sha224_init(SHA224Context* ctx);
void sha224_block(SHA224Context* ctx, const uint8_t block[64]);
void sha224_update(SHA224Context* ctx, const uint8_t* data, size_t length);
void sha224_final(SHA224Context* ctx, uint8_t dst[28]);

void sha224(uint8_t dst[28], const uint8_t* src, size_t length);

#endif
