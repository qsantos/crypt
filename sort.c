#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// fix the ordering by reverting all strings (still slower)
#define REVERT_SORT_REVERT 1

#include "util.h"

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
