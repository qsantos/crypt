#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define __64BITS__ (UINTPTR_MAX == 0xffffffffffffffff)

// different ordering, friendlier with unfolding (faster)
#define REVERSE_ENDIAN_ORDERING 1
// fully reverse the endianness of the ordering (slower)
#define FULLY_REVERSE_ORDERING 1
// fix the ordering by reverting all strings (still slower)
#define REVERT_SORT_REVERT 1

#ifdef _WIN32  //  Windows
#include <intrin.h>
uint64_t rdtsc() {
    return __rdtsc();
}
#else  //  Linux/GCC
uint64_t rdtsc() {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return (((uint64_t)hi) << 32) | lo;
}
#endif

static void print(uint8_t* addr, size_t size) {
    while (size-- != 0) {
        printf("%.2x", *addr);
        addr += 1;
    }
}

static char bstrncmp(const uint8_t* addr_a, const uint8_t* addr_b, size_t size) {
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

static void swap(uint8_t* addr_a, uint8_t* addr_b, size_t size) {
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

#if REVERT_SORT_REVERT
static void reverse(uint8_t* addr, size_t size) {
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
#endif

static void quicksort(uint8_t* start, uint8_t* stop, size_t size) {
    if (start + size >= stop) {
        return;
    }

    // find the middle
    size_t count = ((size_t) (stop - start)) / size;
    uint8_t* middle = start + (count / 2) * size;

    // choose pivot (last element)
    uint8_t* pivot = stop - size;
    swap(middle, pivot, size);

    // partition around pivot
    uint8_t* i = start;
    uint8_t* end_j = stop - size;
    for (uint8_t* j = start; j < end_j; j += size) {
        if (bstrncmp(pivot, j, size) > 0) {
            if (i != j) {
                swap(i, j, size);
            }
            i += size;
        }
    }

    // position pivot in between
    swap(i, pivot, size);

    // sort recursively
    quicksort(start, i, size);
    quicksort(i+size, stop, size);
}

int main(int argc, char** argv) {
    FILE* f = fopen("test", "r+");
    if (f == NULL) {
        fprintf(stderr, "Could not open file: %s\n", strerror(errno));
        exit(1);
    }
    fseek(f, 0L, SEEK_END);
    size_t length = (size_t) ftell(f);
    fseek(f, 0L, SEEK_SET);

    uint8_t* mem = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(f), 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "Could not mmap(): %s\n", strerror(errno));
        exit(1);
    }
    size_t size = 32;
    uint8_t* stop = &mem[length];

    uint64_t timing = rdtsc();

#if REVERT_SORT_REVERT
    for (uint8_t* i = mem; i < stop; i += size) {
        reverse(i, size);
    }
#endif

    quicksort(mem, stop, size);

#if REVERT_SORT_REVERT
    for (uint8_t* i = mem; i < stop; i += size) {
        reverse(i, size);
    }
#endif

    timing = (uint64_t) (rdtsc() - timing);

    if (argc > 1) {
        for (uint8_t* i = mem; i < stop; i += size) {
            print(i, size);
            printf("\n");
        }
    } else {
        printf("%e\n", (double) timing);
    }

    //munmap(mem, length * 20);
    fclose(f);
}
