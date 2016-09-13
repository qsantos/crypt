#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

#define __64BITS__ (UINTPTR_MAX == 0xffffffffffffffff)

void print(uint8_t* addr, size_t size);
void bytes_fromhex(uint8_t* dst, const char* hex);
void reverse(uint8_t* addr, size_t size);

char bstrncmp(const uint8_t* addr_a, const uint8_t* addr_b, size_t size);
void memswap(uint8_t* addr_a, uint8_t* addr_b, size_t size);

void bubblesort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length);
void insertsort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length);
void selectsort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length);
void mergesort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length);
void quicksort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length);
void prefixsort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length);

void srand32(uint32_t seed0, uint32_t seed1, uint32_t seed2, uint32_t seed3);
void srand64(uint64_t seed0, uint64_t seed1);
int randbit(void);
uint32_t rand32(void);
uint64_t rand64(void);

void shuffle_quick(uint8_t* start, uint8_t* stop, size_t size);
void shuffle_well(uint8_t* start, uint8_t* stop, size_t size);

#endif
