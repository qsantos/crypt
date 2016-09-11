#include "util.h"

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

// different ordering, friendlier with unfolding (faster) (actuall, SLOWER)
#define REVERSE_ENDIAN_ORDERING 0
// fully reverse the endianness of the ordering (slower)
#define FULLY_REVERSE_ORDERING 0

void print(uint8_t* addr, size_t size) {
    while (size-- != 0) {
        printf("%.2x", *addr);
        addr += 1;
    }
}

void bytes_fromhex(uint8_t* dst, const char* hex) {
    size_t l = strlen(hex);

    if (l % 2 != 0) {
        unsigned int v;
        sscanf(hex, "%1x", &v);
        *dst = (uint8_t) v;
        dst += 1;
        hex += 1;
    }

    while (*hex) {
        unsigned int v;
        sscanf(hex, "%2x", &v);
        *dst = (uint8_t) v;
        dst += 1;
        hex += 2;
    }
}

void reverse(uint8_t* addr, size_t size) {
    uint8_t* addr_a = addr;
    uint8_t* addr_b = addr + size;
#if __64BITS__
    size /= 2;
    while (size >= 8) {
        addr_b -= 8;
        uint64_t tmp = *(uint64_t*)addr_a;
        *(uint64_t*)addr_a = __builtin_bswap64(*(uint64_t*)addr_b);
        *(uint64_t*)addr_b = __builtin_bswap64(tmp);
        addr_a += 8;
        size -= 8;
    }
#endif
    while (addr_a < addr_b) {
        addr_b -= 1;
        uint8_t tmp = *addr_a;
        *addr_a = *addr_b;
        *addr_b = tmp;
        addr_a += 1;
    }
}

char bstrncmp(const uint8_t* addr_a, const uint8_t* addr_b, size_t size) {
#if FULLY_REVERSE_ORDERING
    addr_a += size;
    addr_b += size;
#if __64BITS__
    while (size >= 8) {
        size -= 8;
        addr_a -= 8;
        addr_b -= 8;
        uint64_t value_a = *(uint64_t*) addr_a;
        uint64_t value_b = *(uint64_t*) addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
    }
#else
    while (size >= 4) {
        size -= 4;
        addr_a -= 4;
        addr_b -= 4;
        uint32_t value_a = *(uint32_t*) addr_a;
        uint32_t value_b = *(uint32_t*) addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
    }
#endif
    while (size >= 1) {
        size -= 1;
        addr_a -= 1;
        addr_b -= 1;
        uint8_t value_a = *addr_a;
        uint8_t value_b = *addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
    }
#else
#if REVERSE_ENDIAN_ORDERING
#if __64BITS__
    while (size >= 8) {
        uint64_t value_a = *(uint64_t*) addr_a;
        uint64_t value_b = *(uint64_t*) addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
        size -= 8;
        addr_a += 8;
        addr_b += 8;
    }
#else
    while (size >= 4) {
        uint32_t value_a = *(uint32_t*) addr_a;
        uint32_t value_b = *(uint32_t*) addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
        size -= 4;
        addr_a += 4;
        addr_b += 4;
    }
#endif
#endif
    while (size >= 1) {
        uint8_t value_a = *addr_a;
        uint8_t value_b = *addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
        size -= 1;
        addr_a += 1;
        addr_b += 1;
    }
#endif
    return 0;
}

void memswap(uint8_t* addr_a, uint8_t* addr_b, size_t size) {
#if __64BITS__
    while (size >= 8) {
        uint64_t tmp = *(uint64_t*)addr_a;
        *(uint64_t*)addr_a = *(uint64_t*)addr_b;
        *(uint64_t*)addr_b = tmp;
        size -= 8;
        addr_a += 8;
        addr_b += 8;
    }
#else
    while (size >= 4) {
        uint32_t tmp = *(uint32_t*)addr_a;
        *(uint32_t*)addr_a = *(uint32_t*)addr_b;
        *(uint32_t*)addr_b = tmp;
        size -= 4;
        addr_a += 4;
        addr_b += 4;
    }
#endif
    while (size) {
        uint8_t tmp = *addr_a;
        *addr_a = *addr_b;
        *addr_b = tmp;
        size -= 1;
        addr_a += 1;
        addr_b += 1;
    }
}

void bubblesort(uint8_t* start, uint8_t* stop, size_t size) {
    while (stop > start) {
        uint8_t* previous = start;
        uint8_t* newstop = 0;
        for (uint8_t* current = start + size; current < stop; current += size) {
            if (bstrncmp(previous, current, size) > 0) {
                memswap(previous, current, size);
                newstop = current;
            }
            previous = current;
        }
        stop = newstop;
    }
}

void insertsort(uint8_t* start, uint8_t* stop, size_t size) {
    for (uint8_t* i = start + size; i < stop; i += size) {
        for (uint8_t* j = i; j > start; j -= size) {
            if (bstrncmp(j - size, j, size) > 0) {
                memswap(j - size, j, size);
            } else {
                break;
            }
        }
    }
}

void selectsort(uint8_t* start, uint8_t* stop, size_t size) {
    for (uint8_t* j = start; j < stop; j += size) {
        uint8_t* i_min = j;
        for (uint8_t* i = j+size; i < stop; i += size) {
            if (bstrncmp(i, i_min, size) < 0) {
                i_min = i;
            }
        }
        if (i_min != j) {
            memswap(i_min, j, size);
        }
    }
}

static void merge(uint8_t* start, uint8_t* middle, uint8_t* stop, size_t size, uint8_t* buffer) {
    uint8_t* i = start;
    uint8_t* j = middle;
    uint8_t* k = buffer;
    while (i < middle && j < stop) {
        if (bstrncmp(i, j, size) < 0) {
            memcpy(k, i, size);
            i += size;
        } else {
            memcpy(k, j, size);
            j += size;
        }
        k += size;
    }
    if (i < middle) {
        memcpy(k, i, (size_t) (middle - i));
    } else {
        memcpy(k, j, (size_t) (stop - j));
    }
}
void mergesort(uint8_t* start, uint8_t* stop, size_t size) {
    size_t length = (size_t) (stop - start);

    uint8_t buffer[length];
    uint8_t* buffer0 = start;
    uint8_t* buffer1 = buffer;

    for (size_t scale = size; scale < length<<4; scale *= 2) {
        size_t offset = 0;
        while (offset+scale*2 < length) {
            merge(buffer0 + offset, buffer0 + offset + scale, buffer0 + offset + scale*2, size, buffer1 + offset);
            offset += scale * 2;
        }
        if (offset+scale < length) {
            merge(buffer0+offset, buffer0+offset+scale, buffer0+length, size, buffer1+offset);
        } else {
            memcpy(buffer1 + offset, buffer0 + offset, length - offset);
        }

        // swap buffers
        uint8_t* tmp = buffer0;
        buffer0 = buffer1;
        buffer1 = tmp;
    }
    if (buffer0 == buffer) {
        memcpy(start, buffer, length);
    }
}

static uint8_t* partition(uint8_t* start, uint8_t* stop, size_t size, uint8_t* pivot) {
    uint8_t* i = start;
    for (uint8_t* j = start; j < stop; j += size) {
        if (bstrncmp(pivot, j, size) > 0) {
            if (i != j) {
                memswap(i, j, size);
            }
            i += size;
        }
    }
    return i;
}
void quicksort(uint8_t* start, uint8_t* stop, size_t size) {
    long length = stop - start;
    if (length <= (long) size) {
        return;
    }
    if ((size_t) length < size*8) {
        selectsort(start, stop, size);
        return;
    }

    // choose pivot (middle element) and move it to last position
    size_t count = (size_t) length / size;
    uint8_t* middle = start + (count / 2) * size;
    uint8_t* pivot = stop - size;
    memswap(middle, pivot, size);

    // partition around pivot
    uint8_t* p = partition(start, stop-size, size, pivot);

    // position pivot in between
    memswap(p, pivot, size);

    // sort recursively
    quicksort(start, p, size);
    quicksort(p+size, stop, size);
}
