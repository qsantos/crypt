/*\
 * This is the central part of MD4. The following code handles one block of the
 * input. OP is a target-dependent macro that executes one step of MD4. If
 * LENGTH evaluates to 56 or more, the full state (A, B, C, D) is updated;
 * otherwise, only A is correctly computed, and shortcuts can be taken.
\*/

/*\
 * NOTE:
 * SIMD implementations (MMX, SSE2, AVX2, AVX512) interleave several
 * (respectively 2, 4, 8, 16) independent runs of MD4. This does not help with
 * a single hash but speeds up computation of multiple hashes. In the
 * following, WORD will be referencing to the type relevant to the
 * implementation (i.e. uint32_t, __m64, __m128i, __m256i or __m512i).
\*/

#define MD4_BLOCK( \
        BLOCK, /* WORD*: the block to be processed */ \
        A,B,C,D, /* WORD: the 128 bit state of MD4 */ \
        LENGTH /* in bytes; if less than 56, shortcuts can be taken; */ \
    ) do { \
    WORD* X = (WORD*) BLOCK; \
    \
    WORD previous_A = A; \
    WORD previous_B = B; \
    WORD previous_C = C; \
    WORD previous_D = D; \
    \
    MD4_OP1(A,B,C,D,  0, 3); MD4_OP1(D,A,B,C,  1, 7); MD4_OP1(C,D,A,B,  2,11); MD4_OP1(B,C,D,A,  3,19); \
    MD4_OP1(A,B,C,D,  4, 3); MD4_OP1(D,A,B,C,  5, 7); MD4_OP1(C,D,A,B,  6,11); MD4_OP1(B,C,D,A,  7,19); \
    MD4_OP1(A,B,C,D,  8, 3); MD4_OP1(D,A,B,C,  9, 7); MD4_OP1(C,D,A,B, 10,11); MD4_OP1(B,C,D,A, 11,19); \
    MD4_OP1(A,B,C,D, 12, 3); MD4_OP1(D,A,B,C, 13, 7); MD4_OP1(C,D,A,B, 14,11); MD4_OP1(B,C,D,A, 15,19); \
    \
    MD4_OP2(A,B,C,D,  0, 3); MD4_OP2(D,A,B,C,  4, 5); MD4_OP2(C,D,A,B,  8, 9); MD4_OP2(B,C,D,A, 12,13); \
    MD4_OP2(A,B,C,D,  1, 3); MD4_OP2(D,A,B,C,  5, 5); MD4_OP2(C,D,A,B,  9, 9); MD4_OP2(B,C,D,A, 13,13); \
    MD4_OP2(A,B,C,D,  2, 3); MD4_OP2(D,A,B,C,  6, 5); MD4_OP2(C,D,A,B, 10, 9); MD4_OP2(B,C,D,A, 14,13); \
    MD4_OP2(A,B,C,D,  3, 3); MD4_OP2(D,A,B,C,  7, 5); MD4_OP2(C,D,A,B, 11, 9); MD4_OP2(B,C,D,A, 15,13); \
    \
    /* first look at the "else" block to see the full version */ \
    if (LENGTH <= 4) { \
        /* the input fits in a single block, so we can reverse the final additions */ \
        /* since X[ 4], X[11], X[ 2] and X[ 9] are known, we can reverse the last four steps */ \
        /* since X[ 8], X[15], X[ 6] and X[13] are known, we can also reverse four more steps */ \
        /* since X[12], X[ 3], X[10] and X[ 1] are known, we can also reverse four more steps */ \
        /* since we only guarantee the computation of A, we can skip three more steps */ \
        MD4_OP3(A,B,C,D,  0, 3); \
    } else if (LENGTH <= 12) { \
        /* the input fits in a single block, so we can reverse the final additions */ \
        /* since X[ 4], X[11], X[ 2] and X[ 9] are known, we can reverse the last four steps */ \
        /* since X[ 8], X[15], X[ 6] and X[13] are known, we can also reverse four more steps */ \
        /* since we only guarantee the computation of A, we can skip three more steps */ \
        MD4_OP3(A,B,C,D,  0, 3); MD4_OP3(D,A,B,C,  8, 9); MD4_OP3(C,D,A,B,  4,11); MD4_OP3(B,C,D,A, 12,15); \
        MD4_OP3(A,B,C,D,  2, 3); MD4_OP3(D,A,B,C, 10, 9); MD4_OP3(C,D,A,B,  6,11); MD4_OP3(B,C,D,A, 14,15); \
        MD4_OP3(A,B,C,D,  1, 3); \
    } else if (LENGTH < 56) { \
        /* the input fits in a single block, so we can reverse the final additions */ \
        /* since we only guarantee the computation of A, we can skip the last three steps */ \
        MD4_OP3(A,B,C,D,  0, 3); MD4_OP3(D,A,B,C,  8, 9); MD4_OP3(C,D,A,B,  4,11); MD4_OP3(B,C,D,A, 12,15); \
        MD4_OP3(A,B,C,D,  2, 3); MD4_OP3(D,A,B,C, 10, 9); MD4_OP3(C,D,A,B,  6,11); MD4_OP3(B,C,D,A, 14,15); \
        MD4_OP3(A,B,C,D,  1, 3); MD4_OP3(D,A,B,C,  9, 9); MD4_OP3(C,D,A,B,  5,11); MD4_OP3(B,C,D,A, 13,15); \
        MD4_OP3(A,B,C,D,  3, 3); MD4_OP3(D,A,B,C, 11, 9); MD4_OP3(C,D,A,B,  7,11); MD4_OP3(B,C,D,A, 15,15); \
    } else { \
        MD4_OP3(A,B,C,D,  0, 3); MD4_OP3(D,A,B,C,  8, 9); MD4_OP3(C,D,A,B,  4,11); MD4_OP3(B,C,D,A, 12,15); \
        MD4_OP3(A,B,C,D,  2, 3); MD4_OP3(D,A,B,C, 10, 9); MD4_OP3(C,D,A,B,  6,11); MD4_OP3(B,C,D,A, 14,15); \
        MD4_OP3(A,B,C,D,  1, 3); MD4_OP3(D,A,B,C,  9, 9); MD4_OP3(C,D,A,B,  5,11); MD4_OP3(B,C,D,A, 13,15); \
        MD4_OP3(A,B,C,D,  3, 3); MD4_OP3(D,A,B,C, 11, 9); MD4_OP3(C,D,A,B,  7,11); MD4_OP3(B,C,D,A, 15,15); \
        \
        A = ADD(A, previous_A); \
        B = ADD(B, previous_B); \
        C = ADD(C, previous_C); \
        D = ADD(D, previous_D); \
    } \
} while (0)

/*\
 * Below are the target-dependent implementations. An implementation needs:
 *
 * * INIT to reset the state
 * * auxiliary functions F,G,H,I from the MD4 specification
 * * OP to execute a single STEP of MD4 (expecting one of F,G,H,I)
 * * ADD which just adds two values (for the end of the update)
\*/

// generate architecture-dependent functions
#define MD4_GENERATE(TARGET, PREFIX) \
    __attribute__((target(TARGET))) \
    void md4_oneblock_##PREFIX(uint8_t* digest, const uint8_t* block) { \
        WORD A, B, C, D; \
        MD4_INIT(A, B, C, D); \
        MD4_BLOCK(block, A,B,C,D, 64); \
        \
        WORD* Y = (WORD*) digest; \
        Y[0] = A; \
        Y[1] = B; \
        Y[2] = C; \
        Y[3] = D; \
    } \
    \
    __attribute__((target(TARGET))) \
    int md4_test_##PREFIX(const uint8_t* digest, const uint8_t* block) { \
        WORD A, B, C, D; \
        MD4_INIT(A, B, C, D); \
        MD4_BLOCK(block, A,B,C,D, 64); \
        \
        return ANY_EQ(A, *(uint32_t*) digest); \
    } \
