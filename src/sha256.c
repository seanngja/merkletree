#include "sha256.h"

#include <stdint.h>
#include <string.h>

/*
 * Self-contained SHA-256 (FIPS 180-4) in portable C17.
 *
 * Portability notes:
 *  - All words are assembled from / written to bytes explicitly in
 *    big-endian order, so the result does not depend on host endianness.
 *  - Input is only ever read byte by byte (or copied with memcpy), so there
 *    are no unaligned or type-punned memory accesses.
 *  - Every 32-bit operation is performed on uint32_t, so wrap-around is
 *    well defined (unsigned arithmetic), and no compiler intrinsics,
 *    inline assembly or CPU-specific instructions are used.
 */

#define SHA256_BLOCK_BYTES 64

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static const uint32_t H0[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

static uint32_t rotr32(uint32_t x, unsigned int n)
{
    /* n is always in 1..31 here, so neither shift is undefined. */
    return (x >> n) | (x << (32u - n));
}

static uint32_t load_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)((v >> 24) & 0xffu);
    p[1] = (unsigned char)((v >> 16) & 0xffu);
    p[2] = (unsigned char)((v >> 8) & 0xffu);
    p[3] = (unsigned char)(v & 0xffu);
}

static void store_be64(unsigned char *p, uint64_t v)
{
    for (int i = 7; i >= 0; --i) {
        p[i] = (unsigned char)(v & 0xffu);
        v >>= 8;
    }
}

/* Process one 64-byte block, updating the eight-word chaining state. */
static void sha256_compress(uint32_t state[8],
                            const unsigned char block[SHA256_BLOCK_BYTES])
{
    uint32_t w[64];
    for (unsigned int t = 0; t < 16; ++t) {
        w[t] = load_be32(block + 4 * t);
    }
    for (unsigned int t = 16; t < 64; ++t) {
        uint32_t s0 = rotr32(w[t - 15], 7) ^ rotr32(w[t - 15], 18)
                    ^ (w[t - 15] >> 3);
        uint32_t s1 = rotr32(w[t - 2], 17) ^ rotr32(w[t - 2], 19)
                    ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (unsigned int t = 0; t < 64; ++t) {
        uint32_t big_s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + big_s1 + ch + K[t] + w[t];
        uint32_t big_s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = big_s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_init(Sha256Context *ctx)
{
    memcpy(ctx->state, H0, sizeof(H0));
    ctx->total_bytes = 0;
    ctx->buffered = 0;
}

int sha256_update(Sha256Context *ctx, const void *data, size_t length)
{
    if (ctx == NULL || (data == NULL && length != 0)) {
        return -1;
    }
    /* The message length in bits must fit in the 64-bit length field. */
    const uint64_t max_bytes = UINT64_MAX / 8;
    if ((uint64_t)length > max_bytes - ctx->total_bytes) {
        return -1;
    }
    ctx->total_bytes += (uint64_t)length;

    const unsigned char *in = data;
    if (ctx->buffered != 0) {
        size_t take = SHA256_BLOCK_BYTES - ctx->buffered;
        if (take > length) {
            take = length;
        }
        memcpy(ctx->buffer + ctx->buffered, in, take);
        ctx->buffered += take;
        in += take;
        length -= take;
        if (ctx->buffered < SHA256_BLOCK_BYTES) {
            return 0;
        }
        sha256_compress(ctx->state, ctx->buffer);
        ctx->buffered = 0;
    }
    while (length >= SHA256_BLOCK_BYTES) {
        sha256_compress(ctx->state, in);
        in += SHA256_BLOCK_BYTES;
        length -= SHA256_BLOCK_BYTES;
    }
    if (length != 0) {
        memcpy(ctx->buffer, in, length);
        ctx->buffered = length;
    }
    return 0;
}

int sha256_final(Sha256Context *ctx, unsigned char output[SHA256_DIGEST_BYTES])
{
    if (ctx == NULL || output == NULL) {
        return -1;
    }
    uint64_t bit_length = ctx->total_bytes * 8;

    /* Append 0x80, zero-pad to 56 mod 64, then the 64-bit big-endian length. */
    ctx->buffer[ctx->buffered++] = 0x80;
    if (ctx->buffered > SHA256_BLOCK_BYTES - 8) {
        memset(ctx->buffer + ctx->buffered, 0,
               SHA256_BLOCK_BYTES - ctx->buffered);
        sha256_compress(ctx->state, ctx->buffer);
        ctx->buffered = 0;
    }
    memset(ctx->buffer + ctx->buffered, 0,
           SHA256_BLOCK_BYTES - 8 - ctx->buffered);
    store_be64(ctx->buffer + SHA256_BLOCK_BYTES - 8, bit_length);
    sha256_compress(ctx->state, ctx->buffer);

    for (unsigned int i = 0; i < 8; ++i) {
        store_be32(output + 4 * i, ctx->state[i]);
    }
    /* Leave no message-derived state behind in the context. */
    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

int sha256_digest(const void *data, size_t length,
                  unsigned char output[SHA256_DIGEST_BYTES])
{
    if (output == NULL || (data == NULL && length != 0)) {
        return -1;
    }
    Sha256Context ctx;
    sha256_init(&ctx);
    if (sha256_update(&ctx, data, length) != 0) {
        return -1;
    }
    return sha256_final(&ctx, output);
}
