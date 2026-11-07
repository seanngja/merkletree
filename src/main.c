#define _POSIX_C_SOURCE 200809L
#include "merkle.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    MerkleLayout layout = MERKLE_LAYOUT_POINTER;
    const char *positional[3];
    size_t positional_count = 0;
    int layout_seen = 0, options_done = 0;
    int threads = -1; /* -1: sequential builder; >= 1: parallel flat builder */
    for (int i = 1; i < argc; ++i) {
        if (!options_done && strcmp(argv[i], "--") == 0) {
            options_done = 1;
        } else if (!options_done && strcmp(argv[i], "--layout") == 0) {
            if (layout_seen || ++i == argc) {
                fprintf(stderr, "Specify --layout pointer or --layout flat once.\n");
                return EXIT_FAILURE;
            }
            layout_seen = 1;
            if (strcmp(argv[i], "flat") == 0) {
                layout = MERKLE_LAYOUT_FLAT;
            } else if (strcmp(argv[i], "pointer") != 0) {
                fprintf(stderr, "Unknown layout: %s (use pointer or flat).\n", argv[i]);
                return EXIT_FAILURE;
            }
        } else if (!options_done && strcmp(argv[i], "--threads") == 0) {
            size_t parsed;
            if (threads != -1 || ++i == argc || parse_size(argv[i], &parsed) != 0
                || parsed > 4096) {
                fprintf(stderr, "Specify --threads N once, with 1 <= N <= 4096.\n");
                return EXIT_FAILURE;
            }
            threads = (int)parsed;
        } else if ((!options_done && strncmp(argv[i], "--", 2) == 0)
                   || positional_count == 3) {
            fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
            return EXIT_FAILURE;
        } else {
            positional[positional_count++] = argv[i];
        }
    }
    size_t leaves, block_size;
    if (positional_count < 2
        || parse_size(positional[0], &leaves) != 0
        || parse_size(positional[1], &block_size) != 0
        || (leaves & (leaves - 1)) != 0) {
        fprintf(stderr, "Usage: %s [--layout pointer|flat] [--threads N] LEAVES BLOCK_BYTES [INPUT_FILE]\n"
                "Layout defaults to pointer; without --threads both are single-threaded.\n"
                "--threads N uses the parallel OpenMP builder for the chosen layout.\n"
                "LEAVES must be a power of two; BLOCK_BYTES must be positive.\n"
                "Without INPUT_FILE, uses deterministic synthetic bytes.\n", argv[0]);
        return EXIT_FAILURE;
    }
    size_t node_size = layout == MERKLE_LAYOUT_FLAT
                     ? SHA256_DIGEST_BYTES : sizeof(MerkleNode);
    if (leaves > SIZE_MAX / block_size || leaves > SIZE_MAX / 2 + 1
        || block_size > UINT64_MAX / 8
        || leaves + (leaves - 1) > SIZE_MAX / node_size) {
        fprintf(stderr, "Requested size exceeds supported limits.\n");
        return EXIT_FAILURE;
    }
    size_t input_bytes = leaves * block_size;
    unsigned char *data = malloc(input_bytes);
    if (data == NULL) {
        fprintf(stderr, "Unable to allocate %zu input bytes.\n", input_bytes);
        return EXIT_FAILURE;
    }
    if (positional_count == 3) {
        if (read_input(positional[2], data, input_bytes) != 0) {
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
    MerkleStatus status = threads == -1
        ? merkle_build_with_layout(data, leaves, block_size, layout, &tree)
        : merkle_build_parallel(data, leaves, block_size, layout, threads, &tree);
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
    printf("variant=%s_%s\n", threads == -1 ? "sequential" : "parallel",
           layout == MERKLE_LAYOUT_FLAT ? "flat" : "pointer");
    printf("threads=%zu\n", tree->build_threads);
    printf("leaves=%zu\nblock_bytes=%zu\nnodes=%zu\n",
           tree->leaf_count, tree->block_size, tree->node_count);
    printf("node_storage_bytes=%zu\n", tree->node_count * node_size);
    /* Parallel pointer builds double-buffer levels: N + N/2 pointers. */
    size_t workspace_pointers = layout == MERKLE_LAYOUT_FLAT ? 0
                              : threads == -1 ? leaves : leaves + leaves / 2;
    printf("temporary_pointer_bytes=%zu\n",
           workspace_pointers * sizeof(MerkleNode *));
    printf("build_seconds=%.9f\nroot=", seconds);
    const unsigned char *root = merkle_root_hash(tree);
    for (size_t i = 0; i < SHA256_DIGEST_BYTES; ++i) {
        printf("%02x", (unsigned int)root[i]);
    }
    putchar('\n');
    merkle_free(tree);
    return EXIT_SUCCESS;
}
