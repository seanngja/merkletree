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
    /* Atomic: the parallel builder hashes from several threads at once. */
    if (__atomic_add_fetch(&hash_count, 1, __ATOMIC_RELAXED) == hash_fail_at) {
        return -1;
    }
    return __real_sha256_digest(data, length, output);
}

void *__wrap_malloc(size_t size)
{
    /* Atomic: the parallel pointer builder allocates from several threads. */
    if (__atomic_add_fetch(&allocation_count, 1, __ATOMIC_RELAXED) == fail_at) {
        return NULL;
    }
    void *pointer = __real_malloc(size);
    if (pointer != NULL) {
        __atomic_add_fetch(&outstanding, 1, __ATOMIC_RELAXED);
    }
    return pointer;
}

void __wrap_free(void *pointer)
{
    if (pointer != NULL) {
        if (__atomic_fetch_sub(&outstanding, 1, __ATOMIC_RELAXED) == 0) {
            abort();
        }
    }
    __real_free(pointer);
}

int main(void)
{
    unsigned char input[16] = {0};
    const MerkleLayout layouts[] = {MERKLE_LAYOUT_POINTER, MERKLE_LAYOUT_FLAT};
    for (size_t l = 0; l < 2; ++l) {
        /* Pointer: 31 nodes + wrapper + workspace. Flat: buffer + wrapper. */
        size_t allocations = layouts[l] == MERKLE_LAYOUT_FLAT ? 2 : 33;
        hash_fail_at = 0;
        for (size_t failure = 1; failure <= allocations + 1; ++failure) {
            allocation_count = 0;
            fail_at = failure;
            MerkleTree *tree = NULL;
            MerkleStatus status = merkle_build_with_layout(input, 16, 1,
                                                           layouts[l], &tree);
            if (failure <= allocations) {
                if (status != MERKLE_OUT_OF_MEMORY || tree != NULL) {
                    return EXIT_FAILURE;
                }
            } else {
                if (status != MERKLE_OK || tree == NULL
                    || allocation_count != allocations) {
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
            MerkleStatus status = merkle_build_with_layout(input, 16, 1,
                                                           layouts[l], &tree);
            if (status != MERKLE_HASH_ERROR || tree != NULL || outstanding != 0) {
                fprintf(stderr, "Hash failure cleanup failed at hash=%zu\n", failure);
                return EXIT_FAILURE;
            }
        }
    }
    /* Parallel builders, 1 and 4 threads. With 4 threads the n-th malloc or
     * hash call lands on an arbitrary node, so this checks that a failure on
     * any worker cancels the build, reports the right status and frees
     * everything, wherever it happens. */
    /* 64 leaves so that with 4 threads (cutoff 16 parents) the first parent
     * level also runs in parallel, not only the leaves. */
    static unsigned char wide[64];
    const int thread_counts[] = {1, 4};
    for (size_t l = 0; l < 2; ++l) {
        /* Pointer: wrapper + two workspaces + 127 nodes. Flat: wrapper + buffer. */
        size_t allocations = layouts[l] == MERKLE_LAYOUT_FLAT ? 2 : 130;
        for (size_t t = 0; t < 2; ++t) {
            hash_fail_at = 0;
            for (size_t failure = 1; failure <= allocations + 1; ++failure) {
                allocation_count = 0;
                fail_at = failure;
                MerkleTree *tree = NULL;
                MerkleStatus status = merkle_build_parallel(
                    wide, 64, 1, layouts[l], thread_counts[t], &tree);
                if (failure <= allocations
                        ? (status != MERKLE_OUT_OF_MEMORY || tree != NULL)
                        : (status != MERKLE_OK || allocation_count != allocations)) {
                    fprintf(stderr, "Parallel allocation failure %zu "
                            "(layout=%zu, threads=%d) mishandled\n",
                            failure, l, thread_counts[t]);
                    return EXIT_FAILURE;
                }
                merkle_free(tree);
                if (outstanding != 0) {
                    fprintf(stderr, "Parallel leak at allocation failure %zu\n", failure);
                    return EXIT_FAILURE;
                }
            }
            fail_at = 0;
            for (size_t failure = 1; failure <= 127; ++failure) {
                hash_count = 0;
                hash_fail_at = failure;
                MerkleTree *tree = NULL;
                MerkleStatus status = merkle_build_parallel(
                    wide, 64, 1, layouts[l], thread_counts[t], &tree);
                if (status != MERKLE_HASH_ERROR || tree != NULL || outstanding != 0) {
                    fprintf(stderr, "Parallel hash failure %zu (layout=%zu, "
                            "threads=%d) mishandled\n", failure, l, thread_counts[t]);
                    return EXIT_FAILURE;
                }
            }
        }
    }
    puts("Failure tests passed: every allocation/hash failure in all builders cleaned up.");
    return EXIT_SUCCESS;
}
