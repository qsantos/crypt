/*\
 * This is the central part of SHA1. The following code handles one block of
 * the input. OP is a target-dependent macro that executes one step of SHA1. If
 * LENGTH evaluates to 56 or more, the full state (A, B, C, D, E) is updated;
 * otherwise, only A is correctly computed, and shortcuts can be taken.
\*/

/*\
 * NOTE:
 * SIMD implementations (MMX, SSE2, AVX2, AVX512) interleave several
 * (respectively 2, 4, 8, 16) independent runs of SHA1. This does not help with
 * a single hash but speeds up computation of multiple hashes. In the
 * following, WORD will be referencing to the type relevant to the
 * implementation (i.e. uint32_t, __m64, __m128i, __m256i or __m512i).
\*/

#define SHA1_BLOCK( \
        BLOCK, /* the block to be processed */ \
        A,B,C,D,E, /* WORD: the 160 bit state of SHA1 */ \
        LENGTH /* in bytes; if less than 56, shortcuts can be taken; */ \
    ) do { \
    WORD* X = (WORD*) BLOCK; \
    \
    WORD W[80]; \
    \
    for (int t = 0; t < 16; t += 1) { \
        W[t] = BSWAP(X[t]); \
    } \
    \
    for (int t = 16; t < 80; t += 1) { \
        W[t] = ROT(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1); \
    } \
    \
    WORD previous_A = A; \
    WORD previous_B = B; \
    WORD previous_C = C; \
    WORD previous_D = D; \
    WORD previous_E = E; \
    \
    for (int t =  0; t < 20; t += 1) { SHA1_OP(SHA1_F,A,B,C,D,t,0x5A827999); } \
    for (int t = 20; t < 40; t += 1) { SHA1_OP(SHA1_G,A,B,C,D,t,0x6ED9EBA1); } \
    for (int t = 40; t < 60; t += 1) { SHA1_OP(SHA1_H,A,B,C,D,t,0x8F1BBCDC); } \
    for (int t = 60; t < 80; t += 1) { SHA1_OP(SHA1_G,A,B,C,D,t,0xCA62C1D6); } \
    \
    A = ADD(A, previous_A); \
    B = ADD(B, previous_B); \
    C = ADD(C, previous_C); \
    D = ADD(D, previous_D); \
    E = ADD(E, previous_E); \
} while (0)

/*\
 * Below are the target-dependent implementations. An implementation needs:
 *
 * * INIT to reset the state
 * * auxiliary functions F,G,H,I from the SHA1 specification
 * * OP to execute a single STEP of SHA1 (expecting one of F,G,H,I)
 * * ADD which just adds two values (for the end of the update)
\*/

#define SHA1_GENERATE(TARGET, PREFIX) \
    __attribute__((target(TARGET))) \
    void sha1_oneblock_##PREFIX(uint8_t* digest, const uint8_t* block) { \
        WORD A, B, C, D, E; \
        SHA1_INIT(A, B, C, D, E); \
        SHA1_BLOCK(block, A,B,C,D,E, 64); \
        \
        WORD* Y = (WORD*) digest; \
        Y[0] = BSWAP(A); \
        Y[1] = BSWAP(B); \
        Y[2] = BSWAP(C); \
        Y[3] = BSWAP(D); \
        Y[4] = BSWAP(E); \
    } \
    \
    __attribute__((target(TARGET))) \
    int sha1_test_##PREFIX(const uint8_t* digest, const uint8_t* block) { \
        WORD A, B, C, D, E; \
        SHA1_INIT(A, B, C, D, E); \
        SHA1_BLOCK(block, A,B,C,D,E, 64); \
        \
        return ANY_EQ(A, *(uint32_t*) digest); \
    } \

