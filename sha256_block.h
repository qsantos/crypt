/*\
 * This is the central part of SHA-256. The following code handles one block of
 * the input. OP is a target-dependent macro that executes one step of SHA-256.
 * If LENGTH evaluates to 56 or more, the full state (A, B, C, D, E) is
 * updated; otherwise, only A is correctly computed, and shortcuts can be
 * taken.
\*/

/*\
 * NOTE:
 * SIMD implementations (MMX, SSE2, AVX2, AVX512) interleave several
 * (respectively 2, 4, 8, 16) independent runs of SHA-256. This does not help
 * with a single hash but speeds up computation of multiple hashes. In the
 * following, WORD will be referencing to the type relevant to the
 * implementation (i.e. uint32_t, __m64, __m128i, __m256i or __m512i).
\*/

static const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#ifndef ROR
#define ROR(a, s) ROL(a, 32-s)
#endif

#ifndef SHR
#error "Need SHR"
#endif

#ifndef SHA256_INIT
#define SHA256_INIT(A, B, C, D, E, F, G, H) do { \
    A = SET1(0x6a09e667); \
    B = SET1(0xbb67ae85); \
    C = SET1(0x3c6ef372); \
    D = SET1(0xa54ff53a); \
    E = SET1(0x510e527f); \
    F = SET1(0x9b05688c); \
    G = SET1(0x1f83d9ab); \
    H = SET1(0x5be0cd19); \
} while (0)
#endif

#ifndef SHA256_Ch
#define SHA256_Ch(x,y,z) OR(AND(x, y), ANDNOT(x, z))
#endif

#ifndef SHA256_Maj
#define SHA256_Maj(x,y,z) OR(AND(x, y), OR(AND(x, z), AND(y, z)))
#endif

#ifndef SHA256_Sum0
#define SHA256_Sum0(x) XOR(ROR(x, 2), XOR(ROR(x, 13), ROR(x, 22)))
#endif

#ifndef SHA256_Sum1
#define SHA256_Sum1(x) XOR(ROR(x, 6), XOR(ROR(x, 11), ROR(x, 25)))
#endif

#ifndef SHA256_Sigma0
#define SHA256_Sigma0(x) XOR(ROR(x, 7), XOR(ROR(x, 18), SHR(x, 3)))
#endif

#ifndef SHA256_Sigma1
#define SHA256_Sigma1(x) XOR(ROR(x, 17), XOR(ROR(x, 19), SHR(x, 10)))
#endif

#ifndef SHA256_BLOCK
#define SHA256_BLOCK( \
        BLOCK, /* the block to be processed */ \
        A,B,C,D,E,F,G,H, /* WORD: the 256 bit state of SHA-2 */ \
        LENGTH /* in bytes; if less than 56, shortcuts can be taken; */ \
    ) do {\
    WORD* X = (WORD*) BLOCK; \
    WORD W[64]; \
    for (int t = 0; t < 16; t += 1) { \
        W[t] = BSWAP(X[t]); \
    } \
    \
    for (int t = 16; t < 64; t += 1) { \
        W[t] = ADD(SHA256_Sigma1(W[t-2]), ADD(W[t-7], ADD(SHA256_Sigma0(W[t-15]), W[t-16]))); \
    } \
    \
    WORD previous_A = A; \
    WORD previous_B = B; \
    WORD previous_C = C; \
    WORD previous_D = D; \
    WORD previous_E = E; \
    WORD previous_F = F; \
    WORD previous_G = G; \
    WORD previous_H = H; \
    \
    for (int t = 0; t < 64; t += 1) { \
        WORD T1 = ADD(SHA256_Sum1(E), ADD(SHA256_Ch(E,F,G), ADD(SET1(K[t]), ADD(W[t], H)))); \
        WORD T2 = ADD(SHA256_Sum0(A), SHA256_Maj(A,B,C)); \
        H = G; \
        G = F; \
        F = E; \
        E = ADD(D, T1); \
        D = C; \
        C = B; \
        B = A; \
        A = ADD(T1, T2); \
    } \
    \
    A = ADD(A, previous_A); \
    B = ADD(B, previous_B); \
    C = ADD(C, previous_C); \
    D = ADD(D, previous_D); \
    E = ADD(E, previous_E); \
    F = ADD(F, previous_F); \
    G = ADD(G, previous_G); \
    H = ADD(H, previous_H); \
} while (0)
#endif

#define SHA256_GENERATE(TARGET, PREFIX) \
    __attribute__((target(TARGET))) \
    void sha256_oneblock_##PREFIX(uint8_t* digest, const uint8_t* block) { \
        WORD A, B, C, D, E, F, G, H; \
        SHA256_INIT(A, B, C, D, E, F, G, H); \
        SHA256_BLOCK(block, A,B,C,D,E,F,G,H, 64); \
        \
        WORD* Y = (WORD*) digest; \
        Y[0] = BSWAP(A); \
        Y[1] = BSWAP(B); \
        Y[2] = BSWAP(C); \
        Y[3] = BSWAP(D); \
        Y[4] = BSWAP(E); \
        Y[5] = BSWAP(F); \
        Y[6] = BSWAP(G); \
        Y[7] = BSWAP(H); \
    } \
    \
    __attribute__((target(TARGET))) \
    int sha256_test_##PREFIX(const uint8_t* digest, const uint8_t* block) { \
        WORD A, B, C, D, E, F, G, H; \
        SHA256_INIT(A, B, C, D, E, F, G, H); \
        SHA256_BLOCK(block, A,B,C,D,E,F,G,H, 64); \
        \
        return ANY_EQ(A, *(uint32_t*) digest); \
    } \

