#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_BYTES 32

/* Self-contained, portable SHA-256 (FIPS 180-4); no external library.
 * Results are identical on any host regardless of endianness or alignment
 * rules. */

/* Streaming state. Treat the fields as private. */
typedef struct {
    uint32_t state[8];
    uint64_t total_bytes;
    unsigned char buffer[64];
    size_t buffered;
} Sha256Context;

/* One-shot hash.
 * Returns 0 on success, -1 for invalid arguments or a message whose bit
 * length does not fit in 64 bits.
 * data may be NULL only when length is zero. Output must have 32 bytes. */
int sha256_digest(const void *data, size_t length,
                  unsigned char output[SHA256_DIGEST_BYTES]);

/* Incremental interface: init, any number of updates, then final.
 * update/final return 0 on success and -1 on invalid arguments or overflow.
 * final wipes the context; call init again before reusing it. */
void sha256_init(Sha256Context *ctx);
int sha256_update(Sha256Context *ctx, const void *data, size_t length);
int sha256_final(Sha256Context *ctx, unsigned char output[SHA256_DIGEST_BYTES]);

#endif
