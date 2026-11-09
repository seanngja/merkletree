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

static void test_proof_allocation_failures(void)
{
    unsigned char input[16 * 32] = {0};
    MerkleTree *tree = NULL;
    if (merkle_build_with_layout(input, 16, 32, MERKLE_LAYOUT_FLAT, &tree) != MERKLE_OK) {
        fprintf(stderr, "tree build failed\n");
        exit(EXIT_FAILURE);
    }

    // For depth > 0, proof generation makes 2 allocations: MerkleProof struct, proof->steps array
    size_t tree_outstanding = outstanding;
    for (size_t fail_step = 1; fail_step <= 2; ++fail_step) {
        allocation_count = 0;
        fail_at = fail_step;
        MerkleProof *proof = NULL;
        
        MerkleStatus status = merkle_proof_generate(tree, 3, &proof);
        if (status != MERKLE_OUT_OF_MEMORY || proof != NULL) {
            fprintf(stderr, "Proof generation didn't report MERKLE_OUT_OF_MEMORY at failure=%zu\n", fail_step);
            exit(EXIT_FAILURE);
        }
        if (outstanding != tree_outstanding) {
            fprintf(stderr, "Proof generation leaked memory when failure=%zu\n", fail_step);
            exit(EXIT_FAILURE);
        }
    }

    // Verify no heap allocations
    fail_at = 0;
    allocation_count = 0;
    MerkleProof *valid_proof = NULL;
    if (merkle_proof_generate(tree, 3, &valid_proof) != MERKLE_OK) {
        fprintf(stderr, "proof generation failed\n");
        exit(EXIT_FAILURE);
    }

    size_t allocs_before = allocation_count;
    if (merkle_proof_verify(input + 3 * 32, 32, merkle_root_hash(tree), valid_proof) != 1) {
        fprintf(stderr, "proof verification failed\n");
        exit(EXIT_FAILURE);
    }

    if (allocation_count != allocs_before) {
        fprintf(stderr, "merkle_proof_verify allocated dynamic memory on heap\n");
        exit(EXIT_FAILURE);
    }

    merkle_proof_free(valid_proof);
    merkle_free(tree);

    if (outstanding != 0) {
        fprintf(stderr, "cleanup memory failed\n");
        exit(EXIT_FAILURE);
    }
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

    test_proof_allocation_failures();

    puts("Failure tests passed: every allocation/hash failure in both layouts cleaned up.");
    return EXIT_SUCCESS;
}
