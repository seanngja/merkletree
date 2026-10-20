#include "sha256.h"

#include <openssl/evp.h>
#include <stdint.h>

/* OpenSSL owns the hash implementation; tree code uses this shared interface. */
int sha256_digest(const void *data, size_t length,
                  unsigned char output[SHA256_DIGEST_BYTES])
{
    if (output == NULL || (data == NULL && length != 0)
        || length > UINT64_MAX / 8) {
        return -1;
    }
    unsigned int output_length = 0;
    /* Give the library a valid address even for an empty message. */
    const void *input = data != NULL ? data : "";
    if (EVP_Digest(input, length, output, &output_length,
                   EVP_sha256(), NULL) != 1
        || output_length != SHA256_DIGEST_BYTES) {
        return -1;
    }
    return 0;
}
