#ifdef _OPENMP  // TODO
#include <omp.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argparse.h"
#include "util.h"
#include "keyspace.h"
#include "md5.h"
#include "md5_filter.h"

// temporary fix: keep the -n feature during the push of the bruteforce into
// the architecture-dependent code
int do_generate_passwords = 1;

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

    uint32_t filter = md5_getfilterone(args.target, length, 0);

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

        size_t candidates[16];
        size_t a_candidates = args.single ? 1 : 16;
        size_t n_candidates = md5_filterone_avx2(candidates, a_candidates, filter, length, start, count_per_thread);

        // NOTE: should use mutex for printf() but that happens rarely enough
        for (size_t i = 0; i < n_candidates; i += 1) {
            // get candidate
            char key[length+1];
            key[length] = '\0';
            get_key(key, length, candidates[i]);

            // check complete digest
            uint8_t digest[16];
            md5(digest, (uint8_t*) key, length);
            if (bstrncmp(digest, args.target, 16) != 0) {
                continue;
            }

            // this is an actual hit
            printf("%s\n", key);
            if (args.single) {
                exit(0);  // terminate all threads
            }
        }
    }

    return 0;
}
