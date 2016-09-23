#ifdef _OPENMP  // TODO
#include <omp.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argparse.h"
#include "util.h"
#include "keyspace.h"
#include "md5_simd.h"

// parsed arguments
static struct {
    uint8_t target[64];
    int jobs;
    int single;
} args = {{0}, 1, 0};

static void argparse(int argc, char** argv) {
    usage_string = (
    "Usage: %s [OPTIONS] DIGEST\n"
    "Try and find the preimage of DIGEST\n"
    "\n"
    "DIGEST must be given as an hexadecimal string\n"
    "\n"
    "  -1 --single        stop at first preimage found\n"
    "  -j --jobs N        run on N threads (0 = auto)\n"
    "  -h --help          display this help and exit\n"
    "\n"
    "EXAMPLE\n"
    "  bruteforce e80b5017098950fc58aad83c8c14978e\n"
    );

    size_t positional_arguments_read = 0;
    arginfo.argc = argc;
    arginfo.argv = argv;
    for (arginfo.argi = 1; arginfo.argi < argc; arginfo.argi++) {
        arginfo.arg = argv[arginfo.argi];
        if (arg_is("--help", "-h")) {
            usage(NULL);
        } else if (arg_is("--single", "-1")) {
            args.single = 1;
        } else if (arg_is("--jobs", "-j")) {
            args.jobs = (int) arg_get_int();
        } else if (arginfo.arg[0] == '-') {
            usage("unknown option '%s'", arginfo.arg);
        } else if (positional_arguments_read == 0) {
            if (bytes_fromhex(args.target, arginfo.arg) < 0) {
                usage("invalid digest '%s'", arginfo.arg);
            }
            positional_arguments_read += 1;
        } else {
            usage("too many arguments");
        }
    }
    if (positional_arguments_read < 1) {
        usage("too few arguments");
    }
}

int main(int argc, char** argv) {
    argparse(argc, argv);

    size_t length = 6;

    size_t count = 1;
    for (size_t i = 0; i < length; i += 1) {
        count *= charset_length;
    }

    size_t stride = 8;

    if (args.jobs >= 1) {
        omp_set_num_threads(args.jobs);
    }
    #pragma omp parallel
    {
        size_t thread_id = (size_t) omp_get_thread_num();
        size_t n_threads = (size_t) omp_get_num_threads();
        size_t count_per_thread = count / n_threads;
        size_t start = count_per_thread * thread_id;
        fprintf(stderr, "Started thread no %zu / %zu <- keyspace[%zu:%zu]\n",
               thread_id+1, n_threads, start, start + count);

        uint8_t block[1024] __attribute__((aligned(32)));
        uint8_t digests[128];
        const char* ptrs[1024];
        size_t index_stride = (count_per_thread + stride - 1) / stride;
        md5_pad(block, length, stride);
        set_keys(block, ptrs, length, stride, start, index_stride);

        size_t n_iterations = (count_per_thread + stride - 1) / stride;
        for (size_t i = 0; i < n_iterations; i += 1) {
            // check whether any of the interleaved candidates match
            if (md5_test_avx2(args.target, block)) {
                // if so, re-compute the full hash (happens rarely enough)
                // and redo a full comparison
                md5_oneblock_avx2(digests, block);
                for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
                    uint8_t digest[16];
                    uninterleave(digest, digests, 16, stride, interleaf);
                    if (bstrncmp(digest, args.target, 16) != 0) {
                        // not an actuall match
                        continue;
                    }

                    // the hash completely matches the target
                    char buffer[length+1];
                    size_t index = start + interleaf*index_stride + i;
                    get_key(buffer, length, index);
                    buffer[length] = '\0';
                    printf("%s\n", buffer);

                    if (args.single) {
                        exit(0);
                    }
                }
            }

            // proceed to next candidate
            next_keys(block, ptrs, length, stride);
        }
    }

    return 0;
}
