#include "merkle.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>


/* Hash table helpers */
static inline size_t hash_to_bucket(const unsigned char hash[SHA256_DIGEST_BYTES], size_t bucket_count)
{
    uint64_t prefix;
    memcpy(&prefix, hash, sizeof(prefix));
    return (size_t)(prefix % bucket_count);
}

static MerkleLeafMap *leaf_map_create(size_t leaf_count)
{
    MerkleLeafMap *map = malloc(sizeof(*map));
    if (map == NULL) {
        return NULL;
    }

    map->bucket_count = leaf_count > 0 ? leaf_count : 1;

    map->buckets = malloc(map->bucket_count * sizeof(MerkleHashEntry *));
    if (map->buckets == NULL) {
        free(map);
        return NULL;
    }
    memset(map->buckets, 0, map->bucket_count * sizeof(MerkleHashEntry *));
    return map;
}

static int leaf_map_insert(MerkleLeafMap *map, const unsigned char hash[SHA256_DIGEST_BYTES], size_t index)
{
    size_t b = hash_to_bucket(hash, map->bucket_count);
    MerkleHashEntry *entry = malloc(sizeof(*entry));
    if (entry == NULL) {
        return -1;
    }

    memcpy(entry->hash, hash, SHA256_DIGEST_BYTES);
    entry->leaf_index = index;
    entry->next = map->buckets[b];
    map->buckets[b] = entry;
    return 0;
}

static int leaf_map_find(const MerkleLeafMap *map, const unsigned char hash[SHA256_DIGEST_BYTES], size_t *out_index)
{
    if (map == NULL || map->buckets == NULL) {
        return 0;
    }
    size_t b = hash_to_bucket(hash, map->bucket_count);
    for (MerkleHashEntry *e = map->buckets[b]; e != NULL; e = e->next) {
        if (memcmp(e->hash, hash, SHA256_DIGEST_BYTES) == 0) {
            *out_index = e->leaf_index;
            return 1;
        }
    }
    return 0;
}

static void leaf_map_free(MerkleLeafMap *map)
{
    if (map == NULL) {
        return;
    }
    for (size_t i = 0; i < map->bucket_count; ++i) {
        MerkleHashEntry *curr = map->buckets[i];
        while (curr != NULL) {
            MerkleHashEntry *next = curr->next;
            free(curr);
            curr = next;
        }
    }
    free(map->buckets);
    free(map);
}


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
        leaf_map_free(tree->leaf_map);
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
        unsigned char *leaf_slot = tree->flat_hashes + i * SHA256_DIGEST_BYTES;
        if (sha256_digest(data + i * tree->block_size, tree->block_size, leaf_slot) != 0) {
            return MERKLE_HASH_ERROR;
        }
        if (tree->leaf_map != NULL) {
            if (leaf_map_insert(tree->leaf_map, leaf_slot, i) != 0) {
                return MERKLE_OUT_OF_MEMORY;
            }
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

    tree->leaf_map = leaf_map_create(leaf_count);
    if (tree->leaf_map == NULL) {
        free(tree);
        return MERKLE_OUT_OF_MEMORY;
    }

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
        merkle_free(tree);
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
            merkle_free(tree);
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
            merkle_free(tree);
            return MERKLE_HASH_ERROR;
        }
        // Insert leaf hash into lookup map
        if (leaf_map_insert(tree->leaf_map, level[i]->hash, i) != 0) {
            for (size_t j = 0; j <= i; ++j) {
                free_node(level[j]);
            }
            free(level);
            merkle_free(tree);
            return MERKLE_OUT_OF_MEMORY;
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
                merkle_free(tree);
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
                merkle_free(tree);
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
    case MERKLE_HASH_ERROR: return "SHA-256 hashing failed";
    default: return "unknown error";
    }
}


static size_t compute_tree_depth(size_t leaf_count)
{
    size_t depth = 0;
    while (leaf_count > 1) {
        ++depth;
        leaf_count >>= 1;
    }
    return depth;
}

void merkle_proof_free(MerkleProof *proof)
{
    if (proof != NULL) {
        free(proof->steps);
        free(proof);
    }
}

MerkleStatus merkle_proof_generate(const MerkleTree *tree, size_t leaf_index, 
                                   MerkleProof **proof_out)
{
    if (tree == NULL || proof_out == NULL || leaf_index >= tree->leaf_count) {
        return MERKLE_INVALID_ARGUMENT;
    }

    *proof_out = NULL;
    size_t depth = compute_tree_depth(tree->leaf_count);
    MerkleProof *proof = malloc(sizeof(*proof));
    if (proof == NULL) {
        return MERKLE_OUT_OF_MEMORY;
    }
    
    proof->leaf_index = leaf_index;
    proof->depth = depth;
    proof->steps = NULL;

    if (depth > 0) {
        proof->steps = malloc(depth * sizeof(*proof->steps));
        if (proof->steps == NULL) {
            free(proof);
            return MERKLE_OUT_OF_MEMORY;
        }
    }

    if (tree->layout == MERKLE_LAYOUT_FLAT) {
        size_t level_offset = 0;
        size_t level_width = tree->leaf_count;
        size_t current_idx = leaf_index;
        for (size_t d = 0; d < depth; ++d) {
            // Sibling is the adjacent index, flip LSB
            size_t sibling_idx = current_idx ^ 1;
            size_t flat_idx = level_offset + sibling_idx;
            memcpy(proof->steps[d].hash,
                   tree->flat_hashes + flat_idx * SHA256_DIGEST_BYTES,
                   SHA256_DIGEST_BYTES);
            
            // If current index is odd, sibling is left, else right
            proof->steps[d].side = (current_idx & 1) ? MERKLE_SIBLING_LEFT
                                                     : MERKLE_SIBLING_RIGHT;

            level_offset += level_width;
            level_width /= 2;
            current_idx /= 2;
        }
    } else {
        // Pointer layout: traverse down from root using binary search on bits
        const MerkleNode *curr = tree->root;
        for (size_t d = 0; d < depth; ++d) {
            // Path bit at depth d from root: MSB down to LSB
            size_t bit_shift = depth - 1 - d;
            int go_right = (int)((leaf_index >> bit_shift) & 1);

            // In proof, steps[0] is leaf level, steps[depth-1] is near root
            size_t step_idx = bit_shift;
            if (go_right) {
                // Target went right, left child is sibling
                memcpy(proof->steps[step_idx].hash,
                       curr->left->hash,
                       SHA256_DIGEST_BYTES);
                proof->steps[step_idx].side = MERKLE_SIBLING_LEFT;
                curr = curr->right;
            } else {
                // Target went left, right child is sibling
                memcpy(proof->steps[step_idx].hash,
                       curr->right->hash,
                       SHA256_DIGEST_BYTES);
                proof->steps[step_idx].side = MERKLE_SIBLING_RIGHT;
                curr = curr->left;
            }
        }
    }

    *proof_out = proof;
    return MERKLE_OK;
}

int merkle_proof_verify(const void *block, size_t block_size, 
                        const unsigned char expected_root[SHA256_DIGEST_BYTES], 
                        const MerkleProof *proof)
{
    if (proof == NULL || expected_root == NULL || (block == NULL && block_size != 0)) {
        return -1;
    }

    unsigned char current_hash[SHA256_DIGEST_BYTES];
    // Hash raw leaf block to get starting hash
    if (sha256_digest(block, block_size, current_hash) != 0) {
        return -1;
    }

    unsigned char buffer[2 * SHA256_DIGEST_BYTES];
    for (size_t d = 0; d < proof->depth; ++d) {
        if (proof->steps[d].side == MERKLE_SIBLING_LEFT) {
            // Sibling || Current
            memcpy(buffer, proof->steps[d].hash, SHA256_DIGEST_BYTES);
            memcpy(buffer + SHA256_DIGEST_BYTES, current_hash, SHA256_DIGEST_BYTES);
        } else if (proof->steps[d].side == MERKLE_SIBLING_RIGHT) {
            // Current || Sibling
            memcpy(buffer, current_hash, SHA256_DIGEST_BYTES);
            memcpy(buffer + SHA256_DIGEST_BYTES, proof->steps[d].hash, SHA256_DIGEST_BYTES);
        } else {
            return -1;
        }

        if (sha256_digest(buffer, sizeof(buffer), current_hash) != 0) {
            return -1;
        }
    }

    // Verify if recomputed root matches expected root
    return (memcmp(current_hash, expected_root, SHA256_DIGEST_BYTES) == 0) ? 1 : 0;
}


MerkleStatus merkle_proof_generate_hash(const MerkleTree *tree,
                                           const unsigned char leaf_hash[SHA256_DIGEST_BYTES],
                                           MerkleProof **proof_out)
{
    if (tree == NULL || leaf_hash == NULL || proof_out == NULL) {
        return MERKLE_INVALID_ARGUMENT;
    }
    size_t leaf_index = 0;
    if (tree->leaf_map != NULL) {
        if (!leaf_map_find(tree->leaf_map, leaf_hash, &leaf_index)) {
            return MERKLE_INVALID_ARGUMENT; // Hash not found
        }
    } else {
        // Fallback linear scan if map is unbuilt
        int found = 0;
        if (tree->layout == MERKLE_LAYOUT_FLAT) {
            for (size_t i = 0; i < tree->leaf_count; ++i) {
                if (memcmp(tree->flat_hashes + i * SHA256_DIGEST_BYTES, leaf_hash, SHA256_DIGEST_BYTES) == 0) {
                    leaf_index = i;
                    found = 1;
                    break;
                }
            }
        }
        if (!found) {
            return MERKLE_INVALID_ARGUMENT;
        }
    }

    // Reuse existing index-based proof generator
    return merkle_proof_generate(tree, leaf_index, proof_out);
}
