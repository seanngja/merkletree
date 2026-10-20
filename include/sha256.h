#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>

#define SHA256_DIGEST_BYTES 32

/* OpenSSL EVP SHA-256 wrapper.
 * Returns 0 on success, -1 for invalid arguments, an oversized message,
 * or a library hashing failure.
 * data may be NULL only when length is zero. Output must have 32 bytes. */
int sha256_digest(const void *data, size_t length,
                  unsigned char output[SHA256_DIGEST_BYTES]);

#endif
