#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <stdbool.h>
#include <stdint.h>

void Rijndael(const uint8_t* key, const uint8_t* in, uint8_t* out, bool inverse, uint8_t Nk, uint8_t Nr);

void Rijndael128(const uint8_t key[16], const uint8_t in[16], uint8_t out[16], bool inverse);
void Rijndael192(const uint8_t key[24], const uint8_t in[16], uint8_t out[16], bool inverse);
void Rijndael256(const uint8_t key[32], const uint8_t in[16], uint8_t out[16], bool inverse);

#endif
