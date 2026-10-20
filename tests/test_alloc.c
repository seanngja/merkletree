#include "merkle.h"

#include <stdio.h>
#include <stdlib.h>

/* GNU ld --wrap affects calls from our object files, not libc internals. */
void *__real_malloc(size_t size);
void __real_free(void *pointer);
void *__wrap_malloc(size_t size);
void __wrap_free(void *pointer);
int __real_sha256_digest(const void *data, size_t length,
                         unsigned char output[SHA256_DIGEST_BYTES]);
int __wrap_sha256_digest(const void *data, size_t length,
                         unsigned char output[SHA256_DIGEST_BYTES]);

static size_t allocation_count;
static size_t fail_at;
static size_t outstanding;
static size_t hash_count;
static size_t hash_fail_at;

int __wrap_sha256_digest(const void *data, size_t length,
                         unsigned char output[SHA256_DIGEST_BYTES])
{
    if (++hash_count == hash_fail_at) {
        return -1;
    }
    return __real_sha256_digest(data, length, output);
}

void *__wrap_malloc(size_t size)
{
    if (++allocation_count == fail_at) {
        return NULL;
    }
    void *pointer = __real_malloc(size);
    if (pointer != NULL) {
        ++outstanding;
    }
    return pointer;
}

void __wrap_free(void *pointer)
{
    if (pointer != NULL) {
        if (outstanding == 0) {
            abort();
        }
        --outstanding;
    }
    __real_free(pointer);
}

int main(void)
{
    unsigned char input[16] = {0};
    /* 31 nodes, one tree wrapper, one temporary pointer array. */
    for (size_t failure = 1; failure <= 34; ++failure) {
        allocation_count = 0;
        fail_at = failure;
        MerkleTree *tree = NULL;
        MerkleStatus status = merkle_build(input, 16, 1, &tree);
        if (failure <= 33) {
            if (status != MERKLE_OUT_OF_MEMORY || tree != NULL) {
                return EXIT_FAILURE;
            }
        } else {
            if (status != MERKLE_OK || tree == NULL || allocation_count != 33) {
                return EXIT_FAILURE;
            }
            merkle_free(tree);
        }
        if (outstanding != 0) {
            fprintf(stderr, "Leaked allocation when failure=%zu\n", failure);
            return EXIT_FAILURE;
        }
    }
    fail_at = 0;
    for (size_t failure = 1; failure <= 31; ++failure) {
        hash_count = 0;
        hash_fail_at = failure;
        MerkleTree *tree = NULL;
        MerkleStatus status = merkle_build(input, 16, 1, &tree);
        if (status != MERKLE_HASH_ERROR || tree != NULL || outstanding != 0) {
            fprintf(stderr, "Hash failure cleanup failed at hash=%zu\n", failure);
            return EXIT_FAILURE;
        }
    }
    puts("Failure tests passed: every tree allocation and hash failure cleaned up.");
    return EXIT_SUCCESS;
}
