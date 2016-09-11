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

// md2 provides a 16 byte hash
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t total_length;
    size_t bytes_in_buffer;
    uint8_t buffer[16];
    uint8_t C[16];
    uint8_t X[16];
    uint8_t dummy[16];
} MD2Context;

void md2_init(MD2Context* ctx);
void md2_block(MD2Context* ctx, const uint8_t block[16]);
void md2_update(MD2Context* ctx, const uint8_t* data, size_t length);
void md2_final(MD2Context* ctx, uint8_t dst[16]);

void md2(uint8_t dst[16], const uint8_t* src, size_t length);

#endif
