#ifndef MERKLE_H
#define MERKLE_H

#include <stddef.h>
#include "sha256.h"

typedef struct MerkleNode {
    unsigned char hash[SHA256_DIGEST_BYTES];
    struct MerkleNode *left;
    struct MerkleNode *right;
} MerkleNode;

typedef enum {
    MERKLE_LAYOUT_POINTER = 0,
    MERKLE_LAYOUT_FLAT
} MerkleLayout;

typedef struct {
    /* root is used only by pointer layout; flat_hashes only by flat layout. */
    MerkleNode *root;
    size_t leaf_count;
    size_t block_size;
    size_t node_count;
    MerkleLayout layout;
    /* Packed 32-byte hashes: leaves, successive parent levels, then root. */
    unsigned char *flat_hashes;
} MerkleTree;

typedef enum {
    MERKLE_OK = 0,
    MERKLE_INVALID_ARGUMENT,
    MERKLE_SIZE_OVERFLOW,
    MERKLE_OUT_OF_MEMORY,
    MERKLE_HASH_ERROR
} MerkleStatus;

/* Build sequentially, one separately allocated node per hash.
 * leaf_count must be a nonzero power of two; block_size must be nonzero.
 * data must point to at least leaf_count * block_size readable bytes.
 * The tree owns its nodes, but does not retain or own data.
 * On failure *out is NULL (if out is non-NULL); partial allocations are freed.
 * Pass a fresh output slot: an existing tree is not freed by this function.
 * Treat the returned tree and its nodes as read-only until merkle_free(). */
MerkleStatus merkle_build(const void *data, size_t leaf_count,
                         size_t block_size, MerkleTree **out);

/* Same contract as merkle_build(), with explicit storage selection.
 * merkle_build() remains the pointer-layout default. Both are single-threaded. */
MerkleStatus merkle_build_with_layout(const void *data, size_t leaf_count,
                                     size_t block_size, MerkleLayout layout,
                                     MerkleTree **out);

/* Read-only 32-byte root digest for either layout, valid until merkle_free().
 * Returns NULL if tree is NULL. */
const unsigned char *merkle_root_hash(const MerkleTree *tree);

/* Accepts NULL. Frees all nodes and the tree wrapper. */
void merkle_free(MerkleTree *tree);
const char *merkle_status_string(MerkleStatus status);

#endif
