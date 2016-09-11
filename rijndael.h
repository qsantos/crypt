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

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void Rijndael(const uint8_t* key, const uint8_t* in, uint8_t* out, bool inverse, size_t Nk, size_t Nr);

void Rijndael128(const uint8_t key[16], const uint8_t in[16], uint8_t out[16], bool inverse);
void Rijndael192(const uint8_t key[24], const uint8_t in[16], uint8_t out[16], bool inverse);
void Rijndael256(const uint8_t key[32], const uint8_t in[16], uint8_t out[16], bool inverse);

#endif
