#ifndef DES_H
#define DES_H

#include <stdbool.h>
#include <stdint.h>

void DES(const uint8_t key[7], const uint8_t in[8], uint8_t out[8], bool inverse);

#endif
