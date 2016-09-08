#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

// fix the ordering by reverting all strings (still slower)
#define REVERT_SORT_REVERT 1

#include "util.h"

int main(int argc, char** argv) {
    FILE* f = fopen("test", "r+");
    if (f == NULL) {
        err(1, "could not open file '%s'", args.file);
    }

    // measure file length
    if (fseek(f, 0L, SEEK_END) < 0) {
        err(1, "could not seek to end of file");
    }
    size_t length = (size_t) ftell(f);
    if (fseek(f, 0L, SEEK_SET) < 0) {
        err(1, "could not seek to beginning of file");
    }

    uint8_t* mem = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(f), 0);
    fprintf(stderr, "Mapping\n");
    if (mem == MAP_FAILED) {
        err(1, "could not map file to memory");
    }
    fprintf(stderr, "Mapped\n");

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
        fprintf(stderr, "%e\n", (double) timing);
    }

    if (munmap(mem, length) < 0) {
        err(1, "could not unmap");
    }

    if (fclose(f) < 0) {
        err(1, "could not close file");
    }
}
