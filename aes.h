#ifndef AES_H
#define AES_H

#include "rijndael.h"

inline void AES(const uint8_t* KEY, const uint8_t* in, uint8_t* out, bool inverse, uint8_t Nk, uint8_t Nr)
{
	Rijndael(KEY, in, out, inverse, Nk, Nr);
}

void AES128(const uint8_t KEY[16], const uint8_t in[16], uint8_t out[16], bool inverse)
{
	Rijndael128(KEY, in, out, inverse);
}
void AES192(const uint8_t KEY[24], const uint8_t in[16], uint8_t out[16], bool inverse)
{
	Rijndael192(KEY, in, out, inverse);
}

void AES256(const uint8_t KEY[32], const uint8_t in[16], uint8_t out[16], bool inverse)
{
	Rijndael256(KEY, in, out, inverse);
}

#endif
