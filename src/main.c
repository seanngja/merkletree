#define _POSIX_C_SOURCE 200809L
#include "merkle.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int parse_size(const char *text, size_t *value)
{
    if (*text < '0' || *text > '9') {
        return -1;
    }
    errno = 0;
    char *end;
    uintmax_t parsed = strtoumax(text, &end, 10);
    if (errno != 0 || *end != '\0' || parsed == 0 || parsed > SIZE_MAX) {
        return -1;
    }
    *value = (size_t)parsed;
    return 0;
}

/* Fixed seed, reproducible across platforms; not a cryptographic RNG. */
static void generate_input(unsigned char *data, size_t length)
{
    uint32_t state = 1;
    for (size_t i = 0; i < length; ++i) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        data[i] = (unsigned char)state;
    }
}

static int read_input(const char *path, unsigned char *data, size_t length)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return -1;
    }
    size_t received = fread(data, 1, length, file);
    int extra = fgetc(file);
    int failed = received != length || extra != EOF || ferror(file);
    if (fclose(file) != 0) {
        failed = 1;
    }
    if (failed) {
        fprintf(stderr, "Input must contain exactly %zu bytes and be readable.\n",
                length);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    size_t leaves, block_size;
    if ((argc != 3 && argc != 4)
        || parse_size(argv[1], &leaves) != 0
        || parse_size(argv[2], &block_size) != 0
        || (leaves & (leaves - 1)) != 0) {
        fprintf(stderr, "Usage: %s LEAVES BLOCK_BYTES [INPUT_FILE]\n"
                "LEAVES must be a power of two; BLOCK_BYTES must be positive.\n"
                "Without INPUT_FILE, uses deterministic synthetic bytes.\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (leaves > SIZE_MAX / block_size || leaves > SIZE_MAX / 2 + 1
        || block_size > UINT64_MAX / 8
        || leaves + (leaves - 1) > SIZE_MAX / sizeof(MerkleNode)) {
        fprintf(stderr, "Requested size exceeds supported limits.\n");
        return EXIT_FAILURE;
    }
    size_t input_bytes = leaves * block_size;
    unsigned char *data = malloc(input_bytes);
    if (data == NULL) {
        fprintf(stderr, "Unable to allocate %zu input bytes.\n", input_bytes);
        return EXIT_FAILURE;
    }
    if (argc == 4) {
        if (read_input(argv[3], data, input_bytes) != 0) {
            free(data);
            return EXIT_FAILURE;
        }
    } else {
        generate_input(data, input_bytes);
    }

    struct timespec start, finish;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime");
        free(data);
        return EXIT_FAILURE;
    }
    MerkleTree *tree = NULL;
    MerkleStatus status = merkle_build(data, leaves, block_size, &tree);
    if (clock_gettime(CLOCK_MONOTONIC, &finish) != 0) {
        perror("clock_gettime");
        merkle_free(tree);
        free(data);
        return EXIT_FAILURE;
    }
    free(data);
    if (status != MERKLE_OK) {
        fprintf(stderr, "Build failed: %s\n", merkle_status_string(status));
        return EXIT_FAILURE;
    }
    double seconds = (double)(finish.tv_sec - start.tv_sec)
                   + (double)(finish.tv_nsec - start.tv_nsec) / 1e9;
    printf("variant=sequential_pointer\n");
    printf("leaves=%zu\nblock_bytes=%zu\nnodes=%zu\n",
           tree->leaf_count, tree->block_size, tree->node_count);
    printf("node_storage_bytes=%zu\n", tree->node_count * sizeof(MerkleNode));
    printf("temporary_pointer_bytes=%zu\n", leaves * sizeof(MerkleNode *));
    printf("build_seconds=%.9f\nroot=", seconds);
    for (size_t i = 0; i < SHA256_DIGEST_BYTES; ++i) {
        printf("%02x", (unsigned int)tree->root->hash[i]);
    }
    putchar('\n');
    merkle_free(tree);
    return EXIT_SUCCESS;
}
