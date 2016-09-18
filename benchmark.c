#ifdef _OPENMP  // TODO
#include <omp.h>
#endif
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "argparse.h"
#include "util.h"
#include "keyspace.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "md4_simd.h"
#include "md5_simd.h"
#include "sha1_simd.h"

#define FMT_TIT "%-5s"
#define FMT_STR " %11s"
#define FMT_RAT " %6.1f MH/s"

static const size_t n_iterations = 1<<24;

static const char* reference_message;
static const char* reference_digest;

// parsed arguments
static struct {
    int check;
    int passphrases;
    int jobs;
    int md4;
    int md5;
    int sha1;
    int full;
    int x86;
    int mmx;
    int sse2;
    int avx2;
    int avx512;
} args = {0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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
    "     --md4           run benchmarks for MD4\n"
    "     --md5           run benchmarks for MD5\n"
    "     --sha1          run benchmarks for SHA-1\n"
    "  -d --all-digests   equivalent to --md4 --md5 --sha1\n"
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
        } else if (arg_is("--hash", "-n")) {
            args.passphrases = 0;
        } else if (arg_is("--jobs", "-j")) {
            args.jobs = (int) arg_get_uint();
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
        } else if (arg_is("--md4", NULL)) {
            chose_digest = 1;
            args.md4 = 1;
        } else if (arg_is("--md5", NULL)) {
            chose_digest = 1;
            args.md5 = 1;
        } else if (arg_is("--sha1", NULL)) {
            chose_digest = 1;
            args.sha1 = 1;
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

    uint8_t reference[16];
    bytes_fromhex(reference, reference_digest);
    if (bstrncmp(digest, reference, 16) == 0) {
        printf(FMT_STR, "OK");
    } else {
        printf(FMT_STR, "FAIL");
    }
}


static void check_oneblock(
        void(*pad)(uint8_t*,size_t,size_t),
        void(*func)(uint8_t*,const uint8_t*),
        size_t stride
) {
    uint8_t block[1024] __attribute__((aligned(32)));
    pad(block, strlen(reference_message), stride);
    set_key_im(block, reference_message, stride);

    uint8_t interleaved[128];
    func(interleaved, block);

    uint8_t reference[16];
    bytes_fromhex(reference, reference_digest);
    for (size_t interleaf = 0; interleaf < stride; interleaf += 1) {
        uint8_t digest[16];
        uninterleave(digest, interleaved, 16, stride, 0);

        if (bstrncmp(digest, reference, 16) != 0) {
            printf(FMT_STR, "FAIL");
            return;
        }
    }
    printf(FMT_STR, "OK");
}

static void benchmark_full(void(*func)(uint8_t*,const uint8_t*,size_t)) {
    fflush(stdout);
    uint8_t digest[20];
    double timing;
    if (args.jobs != 1) {
        double start = real_clock();
        if (args.jobs > 1) {
            omp_set_num_threads(args.jobs);
        }
        #pragma omp parallel for
        for (size_t i = 0; i < n_iterations; i += 1) {
            func(digest, (uint8_t*) "abcdef", 6);
        }
        timing = real_clock() - start;
    } else {
        clock_t start = clock();
        for (size_t i = 0; i < n_iterations; i += 1) {
            func(digest, (uint8_t*) "abcdef", 6);
        }
        timing = (double) (clock() - start) / CLOCKS_PER_SEC;
    }
    double rate = (double) n_iterations / timing;
    printf(FMT_RAT, rate / 1e6);
}

static void run_n_times(
        void(*pad)(uint8_t*,size_t,size_t),
        void(*func)(uint8_t*,const uint8_t*),
        size_t stride, size_t n
) {
    // prepare block
    uint8_t block[1024] __attribute__((aligned(32)));
    pad(block, 6, stride);

    // prepare key generation
    const char* ptrs[1024];
    set_keys(block, ptrs, 6, stride, 0, 0);

    for (size_t i = 0; i < n; i += 1) {
        uint8_t interleaved[320];
        func(interleaved, block);
        if (args.passphrases) {
            next_keys(block, ptrs, 6, stride);
        }
    }
}

static void benchmark_oneblock(
        void(*pad)(uint8_t*,size_t,size_t),
        void(*func)(uint8_t*,const uint8_t*),
        size_t stride
) {
    fflush(stdout);
    double timing;
    if (args.jobs != 1) {
        double start = real_clock();
        if (args.jobs > 1) {
            omp_set_num_threads(args.jobs);
        }
        #pragma omp parallel
        {
            size_t n_threads = (size_t) omp_get_num_threads();
            run_n_times(pad, func, stride, n_iterations / n_threads);
        }
        timing = real_clock() - start;
    } else {
        clock_t start = clock();
        run_n_times(pad, func, stride, n_iterations);
        timing = (double) (clock() - start) / CLOCKS_PER_SEC;
    }
    double rate = (double) n_iterations / timing * (double) stride;
    printf(FMT_RAT, rate / 1e6);
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
    void(*pad)(uint8_t*,size_t,size_t),
    void(*x86)(uint8_t*,const uint8_t*),
    void(*mmx)(uint8_t*,const uint8_t*),
    void(*sse2)(uint8_t*,const uint8_t*),
    void(*avx2)(uint8_t*,const uint8_t*),
    void(*avx512)(uint8_t*,const uint8_t*)
) {
    printf(FMT_TIT, name);
    if (args.full) {
        check_full(full);
    }
    if (args.x86) {
        check_oneblock(pad, x86, 1);
    }
    if (args.mmx) {
        IF_EXT("mmx", check_oneblock(pad, mmx, 2));
    }
    if (args.sse2) {
        IF_EXT("sse2", check_oneblock(pad, sse2, 4));
    }
    if (args.avx2) {
        IF_EXT("avx2", check_oneblock(pad, avx2, 8));
    }
    if (args.avx512) {
        IF_EXT("avx512f", check_oneblock(pad, avx512, 16));
    }
    printf("\n");
}

#define CHECK_ALL(NAME, PREFIX, MESSAGE, DIGEST) do { \
    reference_message = MESSAGE; \
    reference_digest = DIGEST; \
    check_all(NAME, PREFIX, PREFIX##_pad, \
              PREFIX##_oneblock_x86, PREFIX##_oneblock_mmx, \
              PREFIX##_oneblock_sse2, PREFIX##_oneblock_avx2, \
              PREFIX##_oneblock_avx512); \
} while (0)

static void benchmark_all(const char* name,
    void(*full)(uint8_t*,const uint8_t*,size_t),
    void(*pad)(uint8_t*,size_t,size_t),
    void(*x86)(uint8_t*,const uint8_t*),
    void(*mmx)(uint8_t*,const uint8_t*),
    void(*sse2)(uint8_t*,const uint8_t*),
    void(*avx2)(uint8_t*,const uint8_t*),
    void(*avx512)(uint8_t*,const uint8_t*)
) {
    printf(FMT_TIT, name);
    if (args.full) {
        benchmark_full(full);
    }
    if (args.x86) {
        benchmark_oneblock(pad, x86, 1);
    }
    if (args.mmx) {
        IF_EXT("mmx", benchmark_oneblock(pad, mmx, 2));
    }
    if (args.sse2) {
        IF_EXT("sse2", benchmark_oneblock(pad, sse2, 4));
    }
    if (args.avx2) {
        IF_EXT("avx2", benchmark_oneblock(pad, avx2, 8));
    }
    if (args.avx512) {
        IF_EXT("avx512f", benchmark_oneblock(pad, avx512, 16));
    }
    printf("\n");
}

#define BENCHMARK_ALL(NAME, PREFIX) do { \
    benchmark_all(NAME, PREFIX, PREFIX##_pad, \
                  PREFIX##_oneblock_x86, PREFIX##_oneblock_mmx, \
                  PREFIX##_oneblock_sse2, PREFIX##_oneblock_avx2, \
                  PREFIX##_oneblock_avx512); \
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
        if (args.md4) {
            CHECK_ALL("MD4", md4, "message digest", "d9130a8164549fe818874806e1c7014b");
        }
        if (args.md5) {
            CHECK_ALL("MD5", md5, "message digest", "f96b697d7cb7938d525a2f31aaf161d0");
        }
        if (args.sha1) {
            CHECK_ALL("SHA-1", sha1, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
        }
    } else {
        if (args.md4) {
            BENCHMARK_ALL("MD4", md4);
        }
        if (args.md5) {
            BENCHMARK_ALL("MD5", md5);
        }
        if (args.sha1) {
            BENCHMARK_ALL("SHA-1", sha1);
        }
    }

    return 0;
}
