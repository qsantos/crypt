#define _POSIX_C_SOURCE 1 // for fileno()
#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/mman.h>

// fix the ordering by reverting all strings (still slower)
#define REVERT_SORT_REVERT 0

#include "util.h"
#include "argparse.h"

// parsed arguments
static struct {
    size_t blocksize;
    char* file;
    int shuffle;
    int check;
    int timing;
    uint8_t dummy[4];
} args = {0, 0, 0, 0, 0, {0}};

static void argparse(int argc, char** argv) {
    usage_string = (
    "Usage: %s [OPTIONS] BLOCKSIZE FILE\n"
    "Sort binary blocks in a size.\n"
    "\n"
    "Assuming FILE is made of contiguous blocks of BLOCKSIZE bytes, this\n"
    "shorts them in lexicographical order.\n"
    "\n"
    "  -R --shuffle       shuffle the file\n"
    "  -c --check         check that the file is well ordered; do not sort\n"
    "  -t --timing        measure approximate time used\n"
    "  -h --help          display this help and exit\n"
    );

    size_t positional_arguments_read = 0;
    arginfo.argc = argc;
    arginfo.argv = argv;
    for (arginfo.argi = 1; arginfo.argi < argc; arginfo.argi++) {
        arginfo.arg = argv[arginfo.argi];
        if (arg_is("--help", "-h")) {
            usage(NULL);
        } else if (arg_is("--shuffle", "-R")) {
            args.shuffle = 1;
        } else if (arg_is("--check", "-c")) {
            args.check = 1;
        } else if (arg_is("--timing", "-t")) {
            args.timing = 1;
        } else if (arginfo.arg[0] == '-') {
            usage("unknown option '%s'", arginfo.arg);
        } else if (positional_arguments_read == 0) {
            args.blocksize = strtoul(arginfo.arg, NULL, 0);  // TODO
            positional_arguments_read += 1;
        } else if (positional_arguments_read == 1) {
            args.file = arginfo.arg;
            positional_arguments_read += 1;
        } else {
            usage("too many arguments");
        }
    }
    if (positional_arguments_read < 2) {
        usage("too few arguments");
    }
}

int main(int argc, char** argv) {
    // parse arguments
    argparse(argc, argv);

    // open file
    FILE* f = fopen(args.file, "r+");
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

    // map file to memory
    uint8_t* mem = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(f), 0);
    if (mem == MAP_FAILED) {
        err(1, "could not map file to memory");
    }

    size_t size = args.blocksize;
    uint8_t* stop = &mem[length];

    clock_t timing = clock();

#if REVERT_SORT_REVERT
    for (uint8_t* i = mem; i < stop; i += size) {
        reverse(i, size);
    }
#endif

    if (args.shuffle) {
        srand32((uint32_t) time(NULL), 0, 0, 0);
        shuffle_quick(mem, mem + length, size);
    }

    if (args.check) {
        size_t index = 1;
        for (uint8_t* i = mem + size; i < stop; i += size) {
            if (bstrncmp(i - size, i, size) > 0) {
                print(i - size, size);
                printf("\n");
                print(i, size);
                printf("\n");
                errx(1, "Record no %zu is out of order", index);
            }
            index += 1;
        }
    }

    if (!args.shuffle && !args.check) {
        prefixsort(mem, stop, size, 0, size);
    }

#if REVERT_SORT_REVERT
    for (uint8_t* i = mem; i < stop; i += size) {
        reverse(i, size);
    }
#endif

    if (args.timing) {
        timing = (clock() - timing);
        fprintf(stderr, "%.1f\n", (double) timing / CLOCKS_PER_SEC);
    }

    if (munmap(mem, length) < 0) {
        err(1, "could not unmap");
    }

    if (fclose(f) < 0) {
        err(1, "could not close file");
    }
}
