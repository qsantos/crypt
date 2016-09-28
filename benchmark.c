#ifdef _OPENMP  // TODO
#include <omp.h>
#endif
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "argparse.h"
#include "util.h"
#include "keyspace.h"
#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "md4_filter.h"
#include "md5_filter.h"
#include "sha1_filter.h"
#include "sha256_filter.h"

#define FMT_TIT "%-7s"
#define FMT_STR " %11s"
#define FMT_RAT " %6.1f MH/s"
#define FMT_CYC " %7.1f c/H"

/*\
 *  TODO
 *  temporary fix: keep the -n feature during the push of the bruteforce into
 *  the architecture-dependent code
\*/
int do_generate_passwords = 1;

static const size_t n_iterations = 1<<10;
static const size_t n_samples = 1<<10;

static const char* reference_message;
static const char* reference_digest;

typedef size_t filterone_f(size_t* candidates, size_t size, uint32_t filter, size_t length, size_t start, size_t count);

// parsed arguments
static struct {
    int check;
    int passphrases;
    int jobs;
    int count_cycles;
    int md2;
    int md4;
    int md5;
    int sha1;
    int sha256;
    int full;
    int x86;
    int mmx;
    int sse2;
    int avx2;
    int avx512;
} args = {0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static void best_arch(void) {
    if (__builtin_cpu_supports("avx512f")) {
        args.avx512 = 1;
    } else if (__builtin_cpu_supports("avx2")) {
        args.avx2 = 1;
    } else if (__builtin_cpu_supports("sse2")) {
        args.sse2 = 1;
    } else if (__builtin_cpu_supports("mmx")) {
        args.mmx = 1;
    } else {
        args.x86 = 1;
    }
}

static void all_archs(void) {
    args.full = 1;
    args.x86 = 1;
    args.mmx = 1;
    args.sse2 = 1;
    args.avx2 = 1;
    args.avx512 = 1;
}

static void all_digests(void) {
    args.md4 = 1;
    args.md5 = 1;
    args.sha1 = 1;
    args.sha256 = 1;
}

static void argparse(int argc, char** argv) {
    usage_string = (
    "Usage: %s [OPTIONS]\n"
    "Run benchmarks\n"
    "\n"
    "Run benchmarks for various implementations of various digest\n"
    "algorithms\n"
    "\n"
    "MODE\n"
    "  -c --check         just check, disable any other MODE options\n"
    "  -p --passphrases   actually create passphrases to hash (default)\n"
    "  -n --hash          just hash, should be slightly faster\n"
    "  -j --jobs N        run on N threads (0 = auto)\n"
    "  -r --real          measure real hash rate (default)\n"
    "  -C --count-cycles  count CPU cycles (better for optimization)\n"
    "\n"
    "ARCHITECTURES\n"
    "     --x86           run benchmarks targeting x86\n"
    "     --mmx           run benchmarks targeting MMX\n"
    "     --sse2          run benchmarks targeting SSE2\n"
    "     --avx2          run benchmarks targeting AVX2\n"
    "     --avx512        run benchmarks targeting AVX-512\n"
    "     --best          run benchmarks for current architecture (default)\n"
    "  -a --all-archs     run benchmarks for all architectures (equivalent\n"
    "                     to `--x86 --mmx --sse2 --avx2 --avx512`)\n"
    "\n"
    "DIGESTS\n"
    "     --md2           run benchmarks for MD2 (*sloow*)\n"
    "     --md4           run benchmarks for MD4\n"
    "     --md5           run benchmarks for MD5\n"
    "     --sha1          run benchmarks for SHA-1\n"
    "     --sha256        run benchmarks for SHA-256\n"
    "  -d --all-digests   equivalent to --md4 --md5 --sha1 --sha256\n"
    "\n"
    "MISCELLANEOUS\n"
    "  -A --all           equivalent to --all-digests --all-archs\n"
    "  -h --help          display this help and exit\n"
    );

    int chose_arch = 0;
    int chose_digest = 0;

    arginfo.argc = argc;
    arginfo.argv = argv;
    for (arginfo.argi = 1; arginfo.argi < argc; arginfo.argi++) {
        arginfo.arg = argv[arginfo.argi];
        if (arg_is("--help", "-h")) {
            usage(NULL);
        } else if (arg_is("--check", "-c")) {
            args.check = 1;
        } else if (arg_is("--passphrases", "-p")) {
            args.passphrases = 1;
            do_generate_passwords = 1;
        } else if (arg_is("--hash", "-n")) {
            args.passphrases = 0;
            do_generate_passwords = 0;
        } else if (arg_is("--jobs", "-j")) {
            args.jobs = (int) arg_get_uint();
        } else if (arg_is("--real", "-r")) {
            args.count_cycles = 0;
        } else if (arg_is("--count-cycles", "-C")) {
            args.count_cycles = 1;
        } else if (arg_is("--x86", NULL)) {
            chose_arch = 1;
            args.x86 = 1;
        } else if (arg_is("--mmx", NULL)) {
            chose_arch = 1;
            args.mmx = 1;
        } else if (arg_is("--sse2", NULL)) {
            chose_arch = 1;
            args.sse2 = 1;
        } else if (arg_is("--avx2", NULL)) {
            chose_arch = 1;
            args.avx2 = 1;
        } else if (arg_is("--avx512", NULL)) {
            chose_arch = 1;
            args.avx512 = 1;
        } else if (arg_is("--all-archs", "-a")) {
            chose_arch = 1;
            all_archs();
        } else if (arg_is("--best", NULL)) {
            chose_digest = 1;
            best_arch();
        } else if (arg_is("--md2", NULL)) {
            chose_digest = 1;
            args.md2 = 1;
        } else if (arg_is("--md4", NULL)) {
            chose_digest = 1;
            args.md4 = 1;
        } else if (arg_is("--md5", NULL)) {
            chose_digest = 1;
            args.md5 = 1;
        } else if (arg_is("--sha1", NULL)) {
            chose_digest = 1;
            args.sha1 = 1;
        } else if (arg_is("--sha256", NULL)) {
            chose_digest = 1;
            args.sha256 = 1;
        } else if (arg_is("--all-digests", "-d")) {
            chose_digest = 1;
            all_digests();
        } else if (arg_is("--all", "-A")) {
            chose_arch = 1;
            all_archs();
            chose_digest = 1;
            all_digests();
        } else if (arginfo.arg[0] == '-') {
            usage("unknown option '%s'", arginfo.arg);
        } else {
            usage("too many arguments");
        }
    }

    if (args.jobs > 1) {
        omp_set_num_threads(args.jobs);
    }

    if (!chose_digest) {
        all_digests();
    }
    if (!chose_arch) {
        best_arch();
    }
}

static void check_full(void(*func)(uint8_t*,const uint8_t*,size_t)) {
    uint8_t digest[16];
    func(digest, (uint8_t*) reference_message, strlen(reference_message));

    uint8_t reference[1024];
    bytes_fromhex(reference, reference_digest);
    if (bstrncmp(digest, reference, 16) == 0) {
        printf(FMT_STR, "OK");
    } else {
        printf(FMT_STR, "FAIL");
    }
}


static void check_filterone(filterone_f filterone) {
    // get the reference of the reference message in the keyspace
    size_t index;
    int ret = key_index(reference_message, &index);
    if (ret < 0) {
        errx(1, "Reference message not in keyspace");
    }

    // get the filter for the reference digest
    uint8_t digest[1024];
    bytes_fromhex(digest, reference_digest);
    // TODO: use digest-specific filter generator
    uint32_t* digest_words = (uint32_t*) digest;
    uint32_t filter = digest_words[0];

    size_t candidates[32];
    size_t length = strlen(reference_message);

    if (filterone(candidates, 32, filter, length, index - 5, 10) == 0) {
        printf(FMT_STR, "FAIL");
        return;
    }

    if (filterone(candidates, 32, filter, length, index + 5, 10) != 0) {
        printf(FMT_STR, "FAIL");
        return;
    }

    printf(FMT_STR, "OK");
}

static void benchmark_full(void(*func)(uint8_t*,const uint8_t*,size_t)) {
    fflush(stdout);

    double real_start = real_clock();
    uint64_t cycles_min = (uint64_t) (-1);
    for (size_t i = 0; i < n_samples; i += 1) {
        uint64_t cycles_start = rdtsc();
        if (args.jobs != 1) {
            #pragma omp parallel for
            for (size_t j = 0; j < n_iterations; j += 1) {
                uint8_t digest[20];
                func(digest, (uint8_t*) "abcdef", 6);
            }
        } else {
            for (size_t j = 0; j < n_iterations; j += 1) {
                uint8_t digest[20];
                func(digest, (uint8_t*) "abcdef", 6);
            }
        }
        uint64_t elapsed = rdtsc() - cycles_start;
        if (elapsed < cycles_min) {
            cycles_min = elapsed;
        }
    }
    double real_elapsed = (real_clock() - real_start);

    if (args.count_cycles) {
        size_t n_total = n_iterations;
        double cycles_per_hash = (double) cycles_min / (double) n_total;
        printf(FMT_CYC, cycles_per_hash);
    } else {
        size_t n_total = n_samples * n_iterations;
        double rate = (double) n_total / real_elapsed;
        printf(FMT_RAT, rate / 1e6);
    }
}

static void run_n_times(filterone_f filterone, size_t n) {
    size_t candidates[1024];
    filterone(candidates, 1024, 0x42424242, 6, 0, n);
}

static void benchmark_filterone(filterone_f func) {
    fflush(stdout);

    double real_start = real_clock();
    uint64_t cycles_min = (uint64_t) (-1);
    for (size_t i = 0; i < n_samples; i += 1) {
        uint64_t cycles_start = rdtsc();
        if (args.jobs != 1) {
            #pragma omp parallel
            {
                size_t n_threads = (size_t) omp_get_num_threads();
                run_n_times(func, n_iterations / n_threads);
            }
        } else {
            run_n_times(func, n_iterations);
        }
        uint64_t elapsed = rdtsc() - cycles_start;
        if (elapsed < cycles_min) {
            cycles_min = elapsed;
        }
    }
    double real_elapsed = (real_clock() - real_start);

    if (args.count_cycles) {
        size_t n_total = n_iterations;
        double cycles_per_hash = (double) cycles_min / (double) n_total;
        printf(FMT_CYC, cycles_per_hash);
    } else {
        size_t n_total = n_samples * n_iterations;
        double rate = (double) n_total / real_elapsed;
        printf(FMT_RAT, rate / 1e6);
    }
}

#define IF_EXT(EXT, COMMAND) do { \
    if (__builtin_cpu_supports(EXT)) { \
        COMMAND; \
    } else { \
        printf(FMT_STR, "-"); \
    } \
} while (0)

static void check_all(const char* name,
    void(*full)(uint8_t*,const uint8_t*,size_t),
    filterone_f x86,
    filterone_f mmx,
    filterone_f sse2,
    filterone_f avx2,
    filterone_f avx512
) {
    printf(FMT_TIT, name);
    if (args.full) {
        check_full(full);
    }
    if (args.x86) {
        check_filterone(x86);
    }
    if (args.mmx) {
        IF_EXT("mmx", check_filterone(mmx));
    }
    if (args.sse2) {
        IF_EXT("sse2", check_filterone(sse2));
    }
    if (args.avx2) {
        IF_EXT("avx2", check_filterone(avx2));
    }
    if (args.avx512) {
        IF_EXT("avx512f", check_filterone(avx512));
    }
    printf("\n");
}

#define CHECK_ALL(NAME, PREFIX, MESSAGE, DIGEST) do { \
    reference_message = MESSAGE; \
    reference_digest = DIGEST; \
    check_all(NAME, PREFIX, \
              PREFIX##_filterone_x86, PREFIX##_filterone_mmx, \
              PREFIX##_filterone_sse2, PREFIX##_filterone_avx2, \
              PREFIX##_filterone_avx512); \
} while (0)

static void benchmark_all(const char* name,
    void(*full)(uint8_t*,const uint8_t*,size_t),
    filterone_f x86,
    filterone_f mmx,
    filterone_f sse2,
    filterone_f avx2,
    filterone_f avx512
) {
    printf(FMT_TIT, name);
    if (args.full) {
        benchmark_full(full);
    }
    if (args.x86) {
        benchmark_filterone(x86);
    }
    if (args.mmx) {
        IF_EXT("mmx", benchmark_filterone(mmx));
    }
    if (args.sse2) {
        IF_EXT("sse2", benchmark_filterone(sse2));
    }
    if (args.avx2) {
        IF_EXT("avx2", benchmark_filterone(avx2));
    }
    if (args.avx512) {
        IF_EXT("avx512f", benchmark_filterone(avx512));
    }
    printf("\n");
}

#define BENCHMARK_ALL(NAME, PREFIX) do { \
    benchmark_all(NAME, PREFIX, \
                  PREFIX##_filterone_x86, PREFIX##_filterone_mmx, \
                  PREFIX##_filterone_sse2, PREFIX##_filterone_avx2, \
                  PREFIX##_filterone_avx512); \
} while (0)

int main(int argc, char** argv) {
    argparse(argc, argv);

    if (args.check) {
        printf("Just checking\n");
    } else {
        printf("Create passphrases: %s\n", args.passphrases ? "yes" : "no");
        if (args.jobs == 0) {
            printf("Threads: auto\n");
        } else {
            printf("Threads: %i\n", args.jobs);
        }
    }

    printf(FMT_TIT, "");
    if (args.full) {
        printf(FMT_STR, "Full");
    }
    if (args.x86) {
        printf(FMT_STR, "x86");
    }
    if (args.mmx) {
        printf(FMT_STR, "MMX");
    }
    if (args.sse2) {
        printf(FMT_STR, "SSE2");
    }
    if (args.avx2) {
        printf(FMT_STR, "AVX2");
    }
    if (args.avx512) {
        printf(FMT_STR, "AVX-512");
    }
    printf("\n");

    if (args.check) {
        if (args.md2) {
            printf(FMT_TIT, "MD2");
            reference_message = "abc";
            reference_digest = "da853b0d3f88d99b30283a69e6ded6bb";
            check_full(md2);
            printf("\n");
        }
        if (args.md4) {
            CHECK_ALL("MD4", md4, "abc", "a448017aaf21d8525fc10ae87aa6729d");
        }
        if (args.md5) {
            CHECK_ALL("MD5", md5, "abc", "900150983cd24fb0d6963f7d28e17f72");
        }
        if (args.sha1) {
            CHECK_ALL("SHA-1", sha1, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
        }
        if (args.sha256) {
            CHECK_ALL("SHA-256", sha256, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }
    } else {
        if (args.md2) {
            printf(FMT_TIT, "MD2");
            if (args.full) {
                benchmark_full(md2);
            }
            printf("\n");
        }
        if (args.md4) {
            BENCHMARK_ALL("MD4", md4);
        }
        if (args.md5) {
            BENCHMARK_ALL("MD5", md5);
        }
        if (args.sha1) {
            BENCHMARK_ALL("SHA-1", sha1);
        }
        if (args.sha256) {
            BENCHMARK_ALL("SHA-256", sha256);
        }
    }

    return 0;
}
