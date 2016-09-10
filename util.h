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

void bubblesort(uint8_t* start, uint8_t* stop, size_t size);
void insertsort(uint8_t* start, uint8_t* stop, size_t size);
void selectsort(uint8_t* start, uint8_t* stop, size_t size);
void mergesort(uint8_t* start, uint8_t* stop, size_t size);
void quicksort(uint8_t* start, uint8_t* stop, size_t size);

uint64_t rdtsc();

#endif
