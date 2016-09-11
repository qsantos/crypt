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
// ctx provides a 64 byte hash
// sha384 provides a 48 byte hash
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t total_length;
    size_t bytes_in_buffer;
    uint8_t buffer[128];
    uint64_t H[8];
} SHA512Context;

void sha512_init(SHA512Context* ctx);
void sha512_block(SHA512Context* ctx, const uint8_t block[128]);
void sha512_update(SHA512Context* ctx, const uint8_t* data, size_t length);
void sha512_final(SHA512Context* ctx, uint8_t dst[64]);

void sha512(uint8_t dst[64], const uint8_t* src, size_t length);


typedef SHA512Context SHA384Context;

void sha384_init(SHA384Context* ctx);
void sha384_block(SHA384Context* ctx, const uint8_t block[128]);
void sha384_update(SHA384Context* ctx, const uint8_t* data, size_t length);
void sha384_final(SHA384Context* ctx, uint8_t dst[48]);

void sha384(uint8_t dst[48], const uint8_t* src, size_t length);

#endif
