#include "merkle.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void free_node(MerkleNode *node)
{
    if (node != NULL) {
        free_node(node->left);
        free_node(node->right);
        free(node);
    }
}

void merkle_free(MerkleTree *tree)
{
    if (tree != NULL) {
        if (tree->layout == MERKLE_LAYOUT_FLAT) {
            free(tree->flat_hashes);
        } else {
            free_node(tree->root);
        }
        free(tree);
    }
}

MerkleStatus merkle_build(const void *data, size_t leaf_count,
                         size_t block_size, MerkleTree **out)
{
    return merkle_build_with_layout(data, leaf_count, block_size,
                                    MERKLE_LAYOUT_POINTER, out);
}

const unsigned char *merkle_root_hash(const MerkleTree *tree)
{
    if (tree == NULL) {
        return NULL;
    }
    if (tree->layout == MERKLE_LAYOUT_FLAT) {
        return tree->flat_hashes + (tree->node_count - 1) * SHA256_DIGEST_BYTES;
    }
    return tree->root->hash;
}

/* All hashes stay in one allocation. Offsets below are measured in nodes. */
static MerkleStatus build_flat(const unsigned char *data, MerkleTree *tree)
{
    tree->flat_hashes = malloc(tree->node_count * SHA256_DIGEST_BYTES);
    if (tree->flat_hashes == NULL) {
        return MERKLE_OUT_OF_MEMORY;
    }
    for (size_t i = 0; i < tree->leaf_count; ++i) {
        if (sha256_digest(data + i * tree->block_size, tree->block_size,
                          tree->flat_hashes + i * SHA256_DIGEST_BYTES) != 0) {
            return MERKLE_HASH_ERROR;
        }
    }
    size_t offset = 0;
    for (size_t width = tree->leaf_count; width > 1; width /= 2) {
        size_t parent_offset = offset + width;
        for (size_t i = 0; i < width / 2; ++i) {
            /* Adjacent children already form the required 64-byte input. */
            if (sha256_digest(tree->flat_hashes + (offset + 2 * i) * SHA256_DIGEST_BYTES,
                              2 * SHA256_DIGEST_BYTES,
                              tree->flat_hashes + (parent_offset + i) * SHA256_DIGEST_BYTES)
                != 0) {
                return MERKLE_HASH_ERROR;
            }
        }
        offset = parent_offset;
    }
    return MERKLE_OK;
}

MerkleStatus merkle_build_with_layout(const void *data, size_t leaf_count,
                                     size_t block_size, MerkleLayout layout,
                                     MerkleTree **out)
{
    if (out == NULL) {
        return MERKLE_INVALID_ARGUMENT;
    }
    *out = NULL;
    if ((layout != MERKLE_LAYOUT_POINTER && layout != MERKLE_LAYOUT_FLAT)
        || data == NULL || leaf_count == 0 || block_size == 0
        || (leaf_count & (leaf_count - 1)) != 0) {
        return MERKLE_INVALID_ARGUMENT;
    }
    if (leaf_count > SIZE_MAX / block_size
        || (layout == MERKLE_LAYOUT_POINTER
            && leaf_count > SIZE_MAX / sizeof(MerkleNode *))
        || leaf_count > SIZE_MAX / 2 + 1
        || block_size > UINT64_MAX / 8) {
        return MERKLE_SIZE_OVERFLOW;
    }
    size_t node_count = leaf_count + (leaf_count - 1);
    size_t node_size = layout == MERKLE_LAYOUT_FLAT
                     ? SHA256_DIGEST_BYTES : sizeof(MerkleNode);
    if (node_count > SIZE_MAX / node_size) {
        return MERKLE_SIZE_OVERFLOW;
    }

    MerkleTree *tree = malloc(sizeof(*tree));
    if (tree == NULL) {
        return MERKLE_OUT_OF_MEMORY;
    }
    tree->root = NULL;
    tree->flat_hashes = NULL;
    tree->layout = layout;
    tree->leaf_count = leaf_count;
    tree->block_size = block_size;
    tree->node_count = node_count;
    if (layout == MERKLE_LAYOUT_FLAT) {
        MerkleStatus status = build_flat(data, tree);
        if (status != MERKLE_OK) {
            merkle_free(tree);
            return status;
        }
        *out = tree;
        return MERKLE_OK;
    }
    /* Temporary traversal workspace, not contiguous node/hash storage.
     * Each entry owns a disjoint subtree during construction. */
    MerkleNode **level = malloc(leaf_count * sizeof(*level));
    if (level == NULL) {
        free(tree);
        return MERKLE_OUT_OF_MEMORY;
    }
    const unsigned char *bytes = data;
    for (size_t i = 0; i < leaf_count; ++i) {
        level[i] = malloc(sizeof(*level[i]));
        if (level[i] == NULL) {
            for (size_t j = 0; j < i; ++j) {
                free_node(level[j]);
            }
            free(level);
            free(tree);
            return MERKLE_OUT_OF_MEMORY;
        }
        level[i]->left = NULL;
        level[i]->right = NULL;
        if (sha256_digest(bytes + i * block_size, block_size,
                          level[i]->hash) != 0) {
            for (size_t j = 0; j <= i; ++j) {
                free_node(level[j]);
            }
            free(level);
            free(tree);
            return MERKLE_HASH_ERROR;
        }
    }

    for (size_t width = leaf_count; width > 1; width /= 2) {
        for (size_t i = 0; i < width / 2; ++i) {
            MerkleNode *parent = malloc(sizeof(*parent));
            if (parent == NULL) {
                /* Earlier pairs now belong to parents in [0, i).
                 * Unconsumed subtrees are still in [2*i, width). */
                for (size_t j = 0; j < i; ++j) {
                    free_node(level[j]);
                }
                for (size_t j = 2 * i; j < width; ++j) {
                    free_node(level[j]);
                }
                free(level);
                free(tree);
                return MERKLE_OUT_OF_MEMORY;
            }
            parent->left = level[2 * i];
            parent->right = level[2 * i + 1];
            unsigned char pair[2 * SHA256_DIGEST_BYTES];
            memcpy(pair, parent->left->hash, SHA256_DIGEST_BYTES);
            memcpy(pair + SHA256_DIGEST_BYTES, parent->right->hash,
                   SHA256_DIGEST_BYTES);
            if (sha256_digest(pair, sizeof(pair), parent->hash) != 0) {
                /* Children still belong to the level array at this point. */
                free(parent);
                for (size_t j = 0; j < i; ++j) {
                    free_node(level[j]);
                }
                for (size_t j = 2 * i; j < width; ++j) {
                    free_node(level[j]);
                }
                free(level);
                free(tree);
                return MERKLE_HASH_ERROR;
            }
            /* Overwrite consumed entries; unread children remain intact. */
            level[i] = parent;
        }
    }
    tree->root = level[0];
    free(level);
    *out = tree;
    return MERKLE_OK;
}

const char *merkle_status_string(MerkleStatus status)
{
    switch (status) {
    case MERKLE_OK: return "success";
    case MERKLE_INVALID_ARGUMENT:
        return "invalid argument (check layout, power-of-two leaf count and nonzero block size)";
    case MERKLE_SIZE_OVERFLOW: return "requested size exceeds supported limits";
    case MERKLE_OUT_OF_MEMORY: return "memory allocation failed";
    case MERKLE_HASH_ERROR: return "OpenSSL SHA-256 hashing failed";
    default: return "unknown error";
    }
}
