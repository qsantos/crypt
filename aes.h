#ifndef AES_H
#define AES_H

#include <stdbool.h>
#include <stdint.h>

void AES(const uint8_t KEY[16], const uint8_t in[16], uint8_t out[16], bool inverse);

#endif
