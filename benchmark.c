#ifdef _OPENMP  // TODO
#include <omp.h>
#endif
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "util.h"
#include "keyspace.h"
#include "md4.h"
#include "md5.h"
#include "md4_simd.h"
#include "md5_simd.h"

#define FMT_TIT "%-5s"
#define FMT_STR " %11s"
#define FMT_RAT " %6.1f MH/s"

static const size_t n_iterations = 1<<24;

static const char* reference_message;
static const char* reference_digest;

static int check = 0;
static int threaded = 0;
static int generate = 1;

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
    uint8_t digest[16];
    double timing;
    if (threaded) {
        double start = real_clock();
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
        uint8_t interleaved[256];
        func(interleaved, block);
        if (generate) {
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
    if (threaded) {
        double start = real_clock();
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
    check_full(full);
    check_oneblock(pad, x86, 1);
    IF_EXT("mmx",     check_oneblock(pad, mmx, 2));
    IF_EXT("sse2",    check_oneblock(pad, sse2, 4));
    IF_EXT("avx2",    check_oneblock(pad, avx2, 8));
    IF_EXT("avx512f", check_oneblock(pad, avx512, 16));
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
    benchmark_full(full);
    benchmark_oneblock(pad, x86, 1);
    IF_EXT("mmx",     benchmark_oneblock(pad, mmx, 2));
    IF_EXT("sse2",    benchmark_oneblock(pad, sse2, 4));
    IF_EXT("avx2",    benchmark_oneblock(pad, avx2, 8));
    IF_EXT("avx512f", benchmark_oneblock(pad, avx512, 16));
    printf("\n");
}

#define BENCHMARK_ALL(NAME, PREFIX) do { \
    benchmark_all(NAME, PREFIX, PREFIX##_pad, \
                  PREFIX##_oneblock_x86, PREFIX##_oneblock_mmx, \
                  PREFIX##_oneblock_sse2, PREFIX##_oneblock_avx2, \
                  PREFIX##_oneblock_avx512); \
} while (0)

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }

    if (strcmp(argv[1], "-c") == 0) {
        check = 1;
    }
    if (strcmp(argv[1], "-nt") == 0) {
        threaded = 1;
        generate = 0;
    }
    if (strcmp(argv[1], "-n") == 0) {
        generate = 0;
    }
    if (strcmp(argv[1], "-t") == 0) {
        threaded = 1;
    }

    if (check) {
        printf("Just checking\n");
    } else {
        printf("Generate keys: %s\n", generate ? "yes" : "no");
        printf("Use multithreading: %s\n", threaded ? "yes" : "no");
    }

    printf(FMT_TIT FMT_STR FMT_STR FMT_STR FMT_STR FMT_STR FMT_STR "\n",
           "", "Full", "x86", "MMX", "SSE2", "AVX2", "AVX-512");

    if (check) {
        CHECK_ALL("MD4", md4, "message digest", "d9130a8164549fe818874806e1c7014b");
        CHECK_ALL("MD5", md5, "message digest", "f96b697d7cb7938d525a2f31aaf161d0");
    } else {
        BENCHMARK_ALL("MD4", md4);
        BENCHMARK_ALL("MD5", md5);
    }

    return 0;
}
