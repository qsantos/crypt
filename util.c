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
    size /= 2;
#if __64BITS__
    while (size >= 8) {
        addr_b -= 8;
        uint64_t tmp = *(uint64_t*)addr_a;
        *(uint64_t*)addr_a = __builtin_bswap64(*(uint64_t*)addr_b);
        *(uint64_t*)addr_b = __builtin_bswap64(tmp);
        addr_a += 8;
        size -= 8;
    }
    if
#else
    while
#endif
    /*while*/ (size >= 4) {
        addr_b -= 4;
        uint32_t tmp = *(uint32_t*)addr_a;
        *(uint32_t*)addr_a = __builtin_bswap32(*(uint32_t*)addr_b);
        *(uint32_t*)addr_b = __builtin_bswap32(tmp);
        addr_a += 4;
        size -= 4;
    }
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
    if
#else
    while
#endif
    /*while*/ (size >= 4) {
        size -= 4;
        addr_a -= 4;
        addr_b -= 4;
        uint32_t value_a = *(uint32_t*) addr_a;
        uint32_t value_b = *(uint32_t*) addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
    }
    if (size >= 2) {
        size -= 2;
        addr_a -= 2;
        addr_b -= 2;
        uint16_t value_a = *addr_a;
        uint16_t value_b = *addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
    }
    if (size >= 1) {
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
    if
#else
    while
#endif
    /*while*/ (size >= 4) {
        uint32_t value_a = *(uint32_t*) addr_a;
        uint32_t value_b = *(uint32_t*) addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
        size -= 4;
        addr_a += 4;
        addr_b += 4;
    }
    if (size >= 2) {
        uint16_t value_a = *(uint16_t*) addr_a;
        uint16_t value_b = *(uint16_t*) addr_b;
        if (value_a != value_b) {
            return value_a < value_b ? -1 : 1;
        }
        size -= 2;
        addr_a += 2;
        addr_b += 2;
    }
    if
#else
    while
#endif
    /*while*/ (size >= 1) {
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
    if
#else
    while
#endif
    /*while*/ (size >= 4) {
        uint32_t tmp = *(uint32_t*)addr_a;
        *(uint32_t*)addr_a = *(uint32_t*)addr_b;
        *(uint32_t*)addr_b = tmp;
        size -= 4;
        addr_a += 4;
        addr_b += 4;
    }
    if (size >= 2) {
        uint16_t tmp = *(uint16_t*)addr_a;
        *(uint16_t*)addr_a = *(uint16_t*)addr_b;
        *(uint16_t*)addr_b = tmp;
        size -= 2;
        addr_a += 2;
        addr_b += 2;
    }
    if (size) {
        uint8_t tmp = *addr_a;
        *addr_a = *addr_b;
        *addr_b = tmp;
    }
}

void bubblesort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length) {
    while (stop > start) {
        uint8_t* previous = start;
        uint8_t* newstop = 0;
        for (uint8_t* current = start + size; current < stop; current += size) {
            if (bstrncmp(previous + key_offset, current + key_offset, key_length) > 0) {
                memswap(previous, current, size);
                newstop = current;
            }
            previous = current;
        }
        stop = newstop;
    }
}

void insertsort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length) {
    for (uint8_t* i = start + size; i < stop; i += size) {
        for (uint8_t* j = i; j > start; j -= size) {
            if (bstrncmp(j - size + key_offset, j + key_offset, key_length) > 0) {
                memswap(j - size, j, size);
            } else {
                break;
            }
        }
    }
}

void selectsort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length) {
    for (uint8_t* j = start; j < stop; j += size) {
        uint8_t* i_min = j;
        for (uint8_t* i = j+size; i < stop; i += size) {
            if (bstrncmp(i + key_offset, i_min + key_offset, key_length) < 0) {
                i_min = i;
            }
        }
        if (i_min != j) {
            memswap(i_min, j, size);
        }
    }
}

static void merge(uint8_t* start, uint8_t* middle, uint8_t* stop, size_t size, uint8_t* buffer, size_t key_offset, size_t key_length) {
    uint8_t* i = start;
    uint8_t* j = middle;
    uint8_t* k = buffer;
    while (i < middle && j < stop) {
        if (bstrncmp(i + key_offset, j + key_offset, key_length) < 0) {
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
void mergesort(uint8_t* start, uint8_t* stop, size_t size, size_t key_length, size_t key_offset) {
    size_t length = (size_t) (stop - start);

    uint8_t buffer[length];
    uint8_t* buffer0 = start;
    uint8_t* buffer1 = buffer;

    for (size_t scale = size; scale < length<<4; scale *= 2) {
        size_t offset = 0;
        while (offset+scale*2 < length) {
            merge(buffer0 + offset, buffer0 + offset + scale, buffer0 + offset + scale*2, size, buffer1 + offset, key_offset, key_length);
            offset += scale * 2;
        }
        if (offset+scale < length) {
            merge(buffer0+offset, buffer0+offset+scale, buffer0+length, size, buffer1+offset, key_offset, key_length);
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

void quicksort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length) {
    long length = stop - start;
    if (length <= (long) size) {
        return;
    }
    if ((size_t) length < size*8) {
        selectsort(start, stop, size, key_offset, key_length);
        return;
    }

    // select pivot
    uint8_t pivot[size];
    memcpy(pivot, start, size);

    // partition around pivot
    uint8_t* left = start;
    uint8_t* right = stop - size;

    while (left <= right) {
        while (bstrncmp(left + key_offset, pivot + key_offset, key_length) < 0) {
            left += size;
        }
        while (bstrncmp(right + key_offset, pivot + key_offset, key_length) > 0) {
            right -= size;
        }
        if (left <= right) {
            if (left != right) {
                memswap(left, right, size);
            }
            left += size;
            right -= size;
        }
    }

    // sort recursively
    quicksort(start, right+size, size, key_offset, key_length);
    quicksort(left, stop, size, key_offset, key_length);
}

void prefixsort(uint8_t* start, uint8_t* stop, size_t size, size_t key_offset, size_t key_length) {
    // count entries per prefix
    size_t counts[256];
    memset(counts, 0, sizeof(counts));
    for (uint8_t* i = start; i < stop; i += size) {
        uint8_t prefix = i[key_offset];
        counts[prefix] += 1;
    }

    // find bucket start for each prefix
    uint8_t* starts[256];
    starts[0] = start;
    for (int i = 1; i < 256; i += 1) {
        starts[i] = starts[i-1] + size * counts[i-1];
    }

    // initialize the current stops of the buckets
    uint8_t* stops[256];
    memcpy(stops, starts, sizeof(stops));

    // add entries to the buckets
    for (int i = 0; i < 255; i += 1) {
        while (stops[i] < starts[i+1]) {
            uint8_t prefix = stops[i][key_offset];
            if (prefix == i) {
                stops[i] += size;
            } else {
                memswap(stops[i], stops[prefix], size);
                stops[prefix] += size;
            }
        }
    }
    stops[255] = stop;

    // sort each bucket
    for (int i = 0; i < 256; i += 1) {
        quicksort(starts[i], stops[i], size, key_offset + 1, key_length - 1);
    }
}

static uint32_t x, y, z, w;
static uint32_t unconsumed_bits;
static size_t n_unconsumed_bits = 0;

void srand32(uint32_t seed0, uint32_t seed1, uint32_t seed2, uint32_t seed3) {
    x = seed0;
    y = seed1;
    z = seed2;
    w = seed3;
}

void srand64(uint64_t seed0, uint64_t seed1) {
    srand32(
        (uint32_t) (seed0 >> 32),
        (uint32_t) seed0,
        (uint32_t) (seed1 >> 32),
        (uint32_t) seed1
    );
}

int randbit(void) {
    if (n_unconsumed_bits == 0) {
        unconsumed_bits = rand32();
        n_unconsumed_bits = 31;
    } else {
        n_unconsumed_bits -= 1;
    }
    int b = unconsumed_bits & 1;
    unconsumed_bits >>= 1;
    return b;
}


uint32_t rand32(void) {
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

uint64_t rand64(void) {
    uint64_t r = rand32();
    return (r << 32) | rand32();
}

static void shuffle_partition(uint8_t* start, uint8_t* stop, size_t size) {
    uint8_t* i = start;
    for (uint8_t* j = start; j < stop; j += size) {
        if (randbit() % 2) {  // random comparison
            if (i != j) {
                memswap(i, j, size);
            }
            i += size;
        }
    }
}

void shuffle_quick(uint8_t* start, uint8_t* stop, size_t size) {
    long length = stop - start;
    if (length <= 1) {
        return;
    }

    // choose pivot (middle element) and move it to last position
    size_t count = (size_t) length / size - 1;
    uint8_t* middle = start + (count / 2) * size;

    // "partition"
    shuffle_partition(start, stop, size);

    // shuffle recursively
    shuffle_quick(start, middle, size);
    shuffle_quick(middle+size, stop, size);
}

void shuffle_well(uint8_t* start, uint8_t* stop, size_t size) {
    size_t length = (size_t) (stop - start) / size;

    for (uint8_t* i = start; i < stop; i+= size) {
        size_t r = rand64() % length;
        uint8_t* j = i + size*r;
        memswap(i, j, size);
        length -= 1;
    }
}
