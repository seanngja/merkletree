#include "merkle.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

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

/* Shared argument and size checks for every constructor. */
static MerkleStatus check_build_args(const void *data, size_t leaf_count,
                                     size_t block_size, MerkleLayout layout)
{
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
    MerkleStatus checked = check_build_args(data, leaf_count, block_size, layout);
    if (checked != MERKLE_OK) {
        return checked;
    }
    size_t node_count = leaf_count + (leaf_count - 1);

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
    tree->build_threads = 1;
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

/* Hash the two adjacent children at node index child into node index parent. */
static int hash_parent(unsigned char *hashes, size_t child, size_t parent)
{
    return sha256_digest(hashes + child * SHA256_DIGEST_BYTES,
                         2 * SHA256_DIGEST_BYTES,
                         hashes + parent * SHA256_DIGEST_BYTES);
}

/* Once a level has fewer than (threads * this) parents, a barrier per level
 * costs more than the hashing it separates, so one thread finishes the top. */
#define MERKLE_MIN_PARENTS_PER_THREAD 4

/* Level-synchronous parallel construction over the flat layout.
 *
 * Dependencies: every node in level k+1 reads two nodes of level k, and
 * nodes within one level are independent. One thread team is created for
 * the whole build; each level is an `omp for` whose implicit barrier
 * guarantees level k is fully written (and flushed) before any thread starts
 * level k+1. Static scheduling gives every thread a contiguous, disjoint
 * output range, so no node is written by two threads and no locks are needed.
 *
 * Errors: a failed hash sets a shared flag. Threads cannot leave a worksharing
 * loop early, and all threads must meet the same sequence of barriers, so
 * remaining iterations are skipped rather than abandoned. */
static MerkleStatus build_flat_parallel(const unsigned char *data,
                                        MerkleTree *tree, int requested)
{
    tree->flat_hashes = malloc(tree->node_count * SHA256_DIGEST_BYTES);
    if (tree->flat_hashes == NULL) {
        return MERKLE_OUT_OF_MEMORY;
    }
    unsigned char *const hashes = tree->flat_hashes;
    const size_t leaf_count = tree->leaf_count;
    const size_t block_size = tree->block_size;
    int failed = 0;
    int team_size = 1;
#ifndef _OPENMP
    (void)requested;
#endif

#pragma omp parallel num_threads(requested) default(none) \
    shared(hashes, data, failed, team_size) \
    firstprivate(leaf_count, block_size)
    {
        int team = 1;
#ifdef _OPENMP
        team = omp_get_num_threads();
        if (omp_get_thread_num() == 0) {
            team_size = team;
        }
#endif
        /* Level 0: leaves. */
#pragma omp for schedule(static)
        for (size_t i = 0; i < leaf_count; ++i) {
            int stop;
#pragma omp atomic read
            stop = failed;
            if (!stop && sha256_digest(data + i * block_size, block_size,
                                       hashes + i * SHA256_DIGEST_BYTES) != 0) {
#pragma omp atomic write
                failed = 1;
            }
        }   /* implicit barrier: all leaves written */

        /* Every thread holds identical private copies of offset/width, so all
         * threads encounter the same sequence of worksharing loops. */
        const size_t cutoff = (size_t)team * MERKLE_MIN_PARENTS_PER_THREAD;
        size_t offset = 0;
        size_t width = leaf_count;
        for (; width / 2 >= cutoff; width /= 2) {
            const size_t parent_offset = offset + width;
#pragma omp for schedule(static)
            for (size_t i = 0; i < width / 2; ++i) {
                int stop;
#pragma omp atomic read
                stop = failed;
                if (!stop && hash_parent(hashes, offset + 2 * i,
                                         parent_offset + i) != 0) {
#pragma omp atomic write
                    failed = 1;
                }
            }   /* implicit barrier: level complete before the next starts */
            offset = parent_offset;
        }

        /* Narrow top levels: one thread, no further barriers needed between
         * them because a single thread executes them in order. */
#pragma omp single
        {
            for (; width > 1 && !failed; width /= 2) {
                const size_t parent_offset = offset + width;
                for (size_t i = 0; i < width / 2; ++i) {
                    if (hash_parent(hashes, offset + 2 * i,
                                    parent_offset + i) != 0) {
                        failed = 1;
                        break;
                    }
                }
                offset = parent_offset;
            }
        }
    }   /* end of parallel region: implicit barrier and join */

    tree->build_threads = (size_t)team_size;
    return failed ? MERKLE_HASH_ERROR : MERKLE_OK;
}

/* Frees every subtree still owned by an array slot (NULL slots are skipped). */
static void free_level(MerkleNode **nodes, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        free_node(nodes[i]);
    }
}

/* Builds parent i from cur[2i] and cur[2i+1] into next[i].
 * Ownership invariant: every live subtree is owned by exactly one slot.
 * On success the parent takes the children and their cur slots are cleared;
 * on failure next[i] is NULL and the children stay owned by cur. */
static MerkleStatus make_parent(MerkleNode **cur, MerkleNode **next, size_t i)
{
    next[i] = NULL;
    MerkleNode *parent = malloc(sizeof(*parent));
    if (parent == NULL) {
        return MERKLE_OUT_OF_MEMORY;
    }
    parent->left = cur[2 * i];
    parent->right = cur[2 * i + 1];
    unsigned char pair[2 * SHA256_DIGEST_BYTES];
    memcpy(pair, parent->left->hash, SHA256_DIGEST_BYTES);
    memcpy(pair + SHA256_DIGEST_BYTES, parent->right->hash, SHA256_DIGEST_BYTES);
    if (sha256_digest(pair, sizeof(pair), parent->hash) != 0) {
        free(parent);
        return MERKLE_HASH_ERROR;
    }
    next[i] = parent;
    cur[2 * i] = NULL;
    cur[2 * i + 1] = NULL;
    return MERKLE_OK;
}

/* One status slot per level (leaves + up to one level per bit of size_t). */
#define MERKLE_MAX_LEVELS (sizeof(size_t) * CHAR_BIT + 1)

/* Level-synchronous parallel construction of a pointer tree.
 *
 * The sequential builder overwrites level[i] in place, which is only safe
 * because one thread visits i in increasing order. In parallel, a thread
 * could overwrite a slot that another thread has yet to read as a child,
 * so two pointer arrays are used: each level reads `cur` and writes `next`,
 * then the arrays swap. The implicit barrier at the end of each `omp for`
 * ensures every thread has finished reading `cur` and writing `next` before
 * the swap makes `next` the input of the following level. Each thread keeps
 * private, identical copies of cur/next/width and swaps them itself, so no
 * extra barrier is needed for the swap.
 *
 * Errors: each level records failures in its own status slot. That slot is
 * written only during its level and read only after that level's barrier,
 * so every thread reads the same value and all threads leave the loop
 * together. Cleanup happens afterwards on one thread, using the ownership
 * invariant documented on make_parent(). Narrow top levels, like the flat
 * builder, run on one thread after the team finishes. */
static MerkleStatus build_pointer_parallel(const unsigned char *data,
                                           MerkleTree *tree, int requested)
{
    const size_t leaf_count = tree->leaf_count;
    const size_t block_size = tree->block_size;
    MerkleNode **cur = malloc(leaf_count * sizeof(*cur));
    MerkleNode **next = leaf_count > 1 ? malloc(leaf_count / 2 * sizeof(*next))
                                       : NULL;
    if (cur == NULL || (leaf_count > 1 && next == NULL)) {
        free(cur);
        free(next);
        return MERKLE_OUT_OF_MEMORY;
    }
    int level_status[MERKLE_MAX_LEVELS] = {0};
    int team_size = 1;
    int status = MERKLE_OK;
    size_t width = leaf_count;
    size_t pending = 0; /* entries of `next` holding a partial level */
#ifndef _OPENMP
    (void)requested;
#endif

#pragma omp parallel num_threads(requested) default(none) \
    shared(data, cur, next, level_status, team_size, status, width, pending) \
    firstprivate(leaf_count, block_size)
    {
        int team = 1, tid = 0;
#ifdef _OPENMP
        team = omp_get_num_threads();
        tid = omp_get_thread_num();
#endif
        /* Level 0: allocate and hash leaves into disjoint slots of cur. */
#pragma omp for schedule(static)
        for (size_t i = 0; i < leaf_count; ++i) {
            MerkleNode *leaf = malloc(sizeof(*leaf));
            cur[i] = leaf;
            int code = MERKLE_OK;
            if (leaf == NULL) {
                code = MERKLE_OUT_OF_MEMORY;
            } else {
                leaf->left = NULL;
                leaf->right = NULL;
                if (sha256_digest(data + i * block_size, block_size,
                                  leaf->hash) != 0) {
                    code = MERKLE_HASH_ERROR;
                }
            }
            if (code != MERKLE_OK) {
#pragma omp atomic write
                level_status[0] = code;
            }
        }   /* implicit barrier: all leaves allocated and hashed */

        MerkleNode **c = cur, **x = next;
        size_t w = leaf_count, level = 0, partial = 0;
        int stop;
#pragma omp atomic read
        stop = level_status[0];
        const size_t cutoff = (size_t)team * MERKLE_MIN_PARENTS_PER_THREAD;
        while (stop == MERKLE_OK && w / 2 >= cutoff) {
            ++level;
#pragma omp for schedule(static)
            for (size_t i = 0; i < w / 2; ++i) {
                int seen;
#pragma omp atomic read
                seen = level_status[level];
                if (seen != MERKLE_OK) {
                    x[i] = NULL; /* skip: children stay owned by c */
                    continue;
                }
                MerkleStatus code = make_parent(c, x, i);
                if (code != MERKLE_OK) {
#pragma omp atomic write
                    level_status[level] = (int)code;
                }
            }   /* implicit barrier: c fully read, x fully written */
#pragma omp atomic read
            stop = level_status[level];
            if (stop != MERKLE_OK) {
                partial = w / 2;
                break;
            }
            MerkleNode **t = c;
            c = x;
            x = t;
            w /= 2;
        }
        if (tid == 0) {
            /* All threads hold identical copies; publish one for cleanup. */
            team_size = team;
            status = stop;
            cur = c;
            next = x;
            width = w;
            pending = partial;
        }
    }   /* end of parallel region: implicit barrier and join */
    (void)level_status; /* only accessed through OpenMP atomics above */

    /* Sequential tail (or cleanup) on the calling thread. */
    for (size_t half = width / 2; status == MERKLE_OK && width > 1;
         width = half, half /= 2) {
        for (size_t i = 0; i < half; ++i) {
            if (status == MERKLE_OK) {
                status = (int)make_parent(cur, next, i);
            } else {
                next[i] = NULL;
            }
        }
        if (status != MERKLE_OK) {
            pending = half;
            break;
        }
        MerkleNode **t = cur;
        cur = next;
        next = t;
    }
    if (status != MERKLE_OK) {
        free_level(cur, width);
        free_level(next, pending);
    } else {
        tree->root = cur[0];
    }
    /* After an odd number of swaps cur/next refer to each other's buffers;
     * both are freed either way. */
    free(cur);
    free(next);
    tree->build_threads = (size_t)team_size;
    return (MerkleStatus)status;
}

MerkleStatus merkle_build_parallel(const void *data, size_t leaf_count,
                                   size_t block_size, MerkleLayout layout,
                                   int num_threads, MerkleTree **out)
{
    if (out == NULL) {
        return MERKLE_INVALID_ARGUMENT;
    }
    *out = NULL;
    if (num_threads < 0) {
        return MERKLE_INVALID_ARGUMENT;
    }
    MerkleStatus status = check_build_args(data, leaf_count, block_size,
                                           layout);
    if (status != MERKLE_OK) {
        return status;
    }
    int requested = 1;
#ifdef _OPENMP
    requested = num_threads > 0 ? num_threads : omp_get_max_threads();
#endif

    MerkleTree *tree = malloc(sizeof(*tree));
    if (tree == NULL) {
        return MERKLE_OUT_OF_MEMORY;
    }
    tree->root = NULL;
    tree->flat_hashes = NULL;
    tree->layout = layout;
    tree->leaf_count = leaf_count;
    tree->block_size = block_size;
    tree->node_count = leaf_count + (leaf_count - 1);
    tree->build_threads = 1;
    status = layout == MERKLE_LAYOUT_FLAT
           ? build_flat_parallel(data, tree, requested)
           : build_pointer_parallel(data, tree, requested);
    if (status != MERKLE_OK) {
        merkle_free(tree);
        return status;
    }
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


/* Pointer layout recursive DFS scan to find leaf index from hash
 * Returns 1 with index in out_idx if found, 
 * Returns 0 on failure */
static int find_leaf_index_pointer(const MerkleNode *node, size_t depth,
                                   const unsigned char hash[SHA256_DIGEST_BYTES],
                                   size_t *curr_idx, size_t *out_idx)
{
    if (node == NULL) {
        return 0;
    }
    if (depth == 0) {
        if (memcmp(node->hash, hash, SHA256_DIGEST_BYTES) == 0) {
            *out_idx = *curr_idx;
            return 1;
        }
        (*curr_idx)++;
        return 0;
    }
    if (find_leaf_index_pointer(node->left, depth - 1, hash, curr_idx, out_idx)) {
        return 1;
    }
    return find_leaf_index_pointer(node->right, depth - 1, hash, curr_idx, out_idx);
}

MerkleStatus merkle_proof_generate_hash(const MerkleTree *tree,
                                        const unsigned char leaf_hash[SHA256_DIGEST_BYTES],
                                        MerkleProof **proof_out)
{
    if (tree == NULL || leaf_hash == NULL || proof_out == NULL) {
        return MERKLE_INVALID_ARGUMENT;
    }

    size_t leaf_index = 0;
    int found = 0;

    if (tree->layout == MERKLE_LAYOUT_FLAT) {
        for (size_t i = 0; i < tree->leaf_count; ++i) {
            if (memcmp(tree->flat_hashes + i * SHA256_DIGEST_BYTES,
                       leaf_hash, SHA256_DIGEST_BYTES) == 0) {
                leaf_index = i;
                found = 1;
                break;
            }
        }
    } else {
        size_t curr = 0;
        size_t depth = compute_tree_depth(tree->leaf_count);
        found = find_leaf_index_pointer(tree->root, depth, leaf_hash, &curr, &leaf_index);
    }

    if (!found) {
        return MERKLE_INVALID_ARGUMENT;
    }
    return merkle_proof_generate(tree, leaf_index, proof_out);
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
