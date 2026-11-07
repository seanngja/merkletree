#include "merkle.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", \
                __FILE__, __LINE__, #expression); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static void check_hash(const void *data, size_t length, const char *expected)
{
    unsigned char digest[SHA256_DIGEST_BYTES];
    char hex[2 * SHA256_DIGEST_BYTES + 1];
    CHECK(sha256_digest(data, length, digest) == 0);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        (void)snprintf(hex + 2 * i, 3, "%02x", (unsigned int)digest[i]);
    }
    CHECK(strcmp(hex, expected) == 0);
}

static size_t check_subtree(const MerkleNode *node, const unsigned char *data,
                            size_t leaves, size_t block_size)
{
    CHECK(node != NULL);
    unsigned char expected[SHA256_DIGEST_BYTES];
    if (leaves == 1) {
        CHECK(node->left == NULL && node->right == NULL);
        CHECK(sha256_digest(data, block_size, expected) == 0);
        CHECK(memcmp(node->hash, expected, sizeof(expected)) == 0);
        return 1;
    }
    CHECK(node->left != node->right);
    size_t left = check_subtree(node->left, data, leaves / 2, block_size);
    size_t right = check_subtree(node->right, data + leaves / 2 * block_size,
                                leaves / 2, block_size);
    unsigned char pair[2 * SHA256_DIGEST_BYTES];
    memcpy(pair, node->left->hash, SHA256_DIGEST_BYTES);
    memcpy(pair + SHA256_DIGEST_BYTES, node->right->hash, SHA256_DIGEST_BYTES);
    CHECK(sha256_digest(pair, sizeof(pair), expected) == 0);
    CHECK(memcmp(node->hash, expected, sizeof(expected)) == 0);
    return 1 + left + right;
}

/* Helper function to test proof verification and corruption scenarios. */
static void run_proof_test_cases(const MerkleTree *tree, const unsigned char *data,
                                 size_t block_size) {
    const unsigned char *root = merkle_root_hash(tree);
    CHECK(root != NULL);

    for (size_t i = 0; i < tree->leaf_count; ++i) {
        MerkleProof *proof = NULL;
        CHECK(merkle_proof_generate(tree, i, &proof) == MERKLE_OK);
        CHECK(proof != NULL);
        CHECK(proof->leaf_index == i);

        const unsigned char *leaf_data = data + i * block_size;

        // Genuine proof must verify
        CHECK(merkle_proof_verify(leaf_data, block_size, root, proof) == 1);

        // Tampered leaf data must be rejected
        unsigned char *corrupted_data = malloc(block_size);
        CHECK(corrupted_data != NULL);
        memcpy(corrupted_data, leaf_data, block_size);
        corrupted_data[0] ^= 0x01;
        CHECK(merkle_proof_verify(corrupted_data, block_size, root, proof) == 0);
        free(corrupted_data);
        
        // Tampered root hash must be rejected
        unsigned char bad_root[SHA256_DIGEST_BYTES];
        memcpy(bad_root, root, SHA256_DIGEST_BYTES);
        bad_root[0] ^= 0x01;
        CHECK(merkle_proof_verify(leaf_data, block_size, bad_root, proof) == 0);

        // Tampered sibling hashes or wrong sides must be rejected
        for (size_t d = 0; d < proof->depth; ++d) {
            proof->steps[d].hash[0] ^= 0x01;    // Flip bit in sibling hash
            CHECK(merkle_proof_verify(leaf_data, block_size, root, proof) == 0);
            proof->steps[d].hash[0] ^= 0x01;    // Restore

            // Invert sibling side
            proof->steps[d].side = (proof->steps[d].side == MERKLE_SIBLING_LEFT)
                                 ? MERKLE_SIBLING_RIGHT : MERKLE_SIBLING_LEFT;
            CHECK(merkle_proof_verify(leaf_data, block_size, root, proof) == 0);
            proof->steps[d].side = (proof->steps[d].side == MERKLE_SIBLING_LEFT)
                                 ? MERKLE_SIBLING_RIGHT : MERKLE_SIBLING_LEFT;
        }

        merkle_proof_free(proof);
    }
}

static void test_merkle_proofs(void)
{
    const size_t block_size = 65;
    for (size_t leaves = 1; leaves <= 64; leaves *= 2) {
        size_t total_bytes = leaves * block_size;
        unsigned char *data = malloc(total_bytes);
        CHECK(data != NULL);
        for (size_t i = 0; i < total_bytes; ++i) {
            data[i] = (unsigned char)(i * 41 + 13);
        }

        MerkleTree *ptr_tree = NULL;
        MerkleTree *flat_tree = NULL;
        CHECK(merkle_build_with_layout(data, leaves, block_size,
                                       MERKLE_LAYOUT_POINTER, &ptr_tree) == MERKLE_OK);
        CHECK(merkle_build_with_layout(data, leaves, block_size,
                                       MERKLE_LAYOUT_FLAT, &flat_tree) == MERKLE_OK);

        // Test all leaves on both layouts
        run_proof_test_cases(ptr_tree, data, block_size);
        run_proof_test_cases(flat_tree, data, block_size);
        
        // Verify pointer tree proof against flat tree proof and vice versa
        for (size_t i = 0; i < leaves; ++i) {
            MerkleProof *ptr_proof = NULL;
            MerkleProof *flat_proof = NULL;
            CHECK(merkle_proof_generate(ptr_tree, i, &ptr_proof) == MERKLE_OK);
            CHECK(merkle_proof_generate(flat_tree, i, &flat_proof) == MERKLE_OK);
            CHECK(ptr_proof->depth == flat_proof->depth);

            for (size_t d = 0; d < ptr_proof->depth; ++d) {
                CHECK(ptr_proof->steps[d].side == flat_proof->steps[d].side);
                CHECK(memcmp(ptr_proof->steps[d].hash, flat_proof->steps[d].hash, 
                             SHA256_DIGEST_BYTES) == 0);
            }

            CHECK(merkle_proof_verify(data + i * block_size, block_size, 
                                      merkle_root_hash(flat_tree), ptr_proof) == 1);
            CHECK(merkle_proof_verify(data + i * block_size, block_size, 
                                      merkle_root_hash(ptr_tree), flat_proof) == 1);
            
            merkle_proof_free(ptr_proof);
            merkle_proof_free(flat_proof);
        }

        merkle_free(ptr_tree);
        merkle_free(flat_tree);
        free(data);
    }
}

int main(void)
{
    check_hash(NULL, 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_hash("abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    unsigned char *million = malloc(1000000);
    CHECK(million != NULL);
    memset(million, 'a', 1000000);
    check_hash(million, 1000000,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    free(million);

    /* Streaming in uneven chunks must match the one-shot digest for lengths
     * straddling the 55/56/64-byte padding boundaries. */
    unsigned char stream_data[300];
    for (size_t i = 0; i < sizeof(stream_data); ++i) {
        stream_data[i] = (unsigned char)(i * 131 + 7);
    }
    for (size_t length = 0; length <= sizeof(stream_data); ++length) {
        unsigned char one_shot[SHA256_DIGEST_BYTES];
        CHECK(sha256_digest(stream_data, length, one_shot) == 0);
        for (size_t chunk = 1; chunk <= 70; chunk += 23) {
            Sha256Context ctx;
            sha256_init(&ctx);
            for (size_t done = 0; done < length;) {
                size_t take = length - done < chunk ? length - done : chunk;
                CHECK(sha256_update(&ctx, stream_data + done, take) == 0);
                done += take;
            }
            unsigned char streamed[SHA256_DIGEST_BYTES];
            CHECK(sha256_final(&ctx, streamed) == 0);
            CHECK(memcmp(one_shot, streamed, sizeof(one_shot)) == 0);
        }
    }

    unsigned char data[16 * 65];
    for (size_t i = 0; i < sizeof(data); ++i) {
        data[i] = (unsigned char)(i * 37 + i / 7);
    }
    for (size_t leaves = 1; leaves <= 16; leaves *= 2) {
        MerkleTree *tree = NULL;
        CHECK(merkle_build(data, leaves, 65, &tree) == MERKLE_OK);
        CHECK(tree->leaf_count == leaves && tree->block_size == 65);
        CHECK(tree->node_count == 2 * leaves - 1);
        CHECK(check_subtree(tree->root, data, leaves, 65) == tree->node_count);
        CHECK(tree->layout == MERKLE_LAYOUT_POINTER && tree->flat_hashes == NULL);
        MerkleTree *flat = NULL;
        CHECK(merkle_build_with_layout(data, leaves, 65, MERKLE_LAYOUT_FLAT,
                                       &flat) == MERKLE_OK);
        CHECK(flat->layout == MERKLE_LAYOUT_FLAT && flat->root == NULL);
        CHECK(flat->leaf_count == leaves && flat->block_size == 65);
        CHECK(flat->node_count == tree->node_count);
        CHECK(memcmp(merkle_root_hash(flat), merkle_root_hash(tree),
                     SHA256_DIGEST_BYTES) == 0);
        /* Compare every stored level with the corresponding pointer nodes. */
        for (size_t width = leaves, offset = 0; ; offset += width, width /= 2) {
            for (size_t i = 0; i < width; ++i) {
                const MerkleNode *node = tree->root;
                for (size_t bit = width / 2; bit != 0; bit /= 2) {
                    node = (i & bit) != 0 ? node->right : node->left;
                }
                CHECK(memcmp(flat->flat_hashes + (offset + i) * SHA256_DIGEST_BYTES,
                             node->hash, SHA256_DIGEST_BYTES) == 0);
            }
            if (width == 1) {
                break;
            }
        }
        merkle_free(flat);
        merkle_free(tree);
    }
    MerkleTree *original = NULL, *modified = NULL, *repeated = NULL;
    CHECK(merkle_build(data, 16, 65, &original) == MERKLE_OK);
    data[17] ^= 1;
    CHECK(merkle_build(data, 16, 65, &modified) == MERKLE_OK);
    CHECK(memcmp(original->root->hash, modified->root->hash,
                 SHA256_DIGEST_BYTES) != 0);
    memset(data, 'a', sizeof(data));
    CHECK(merkle_build(data, 16, 65, &repeated) == MERKLE_OK);
    CHECK(check_subtree(repeated->root, data, 16, 65) == 31);
    merkle_free(original);
    merkle_free(modified);
    merkle_free(repeated);
    merkle_free(NULL);

    MerkleTree *bad = NULL;
    CHECK(merkle_build(NULL, 1, 1, &bad) == MERKLE_INVALID_ARGUMENT);
    CHECK(bad == NULL);
    CHECK(merkle_root_hash(NULL) == NULL);
    CHECK(merkle_build_with_layout(data, 1, 1, (MerkleLayout)99, &bad)
          == MERKLE_INVALID_ARGUMENT);
    CHECK(bad == NULL);
    CHECK(merkle_build_with_layout(NULL, 1, 1, MERKLE_LAYOUT_FLAT, &bad)
          == MERKLE_INVALID_ARGUMENT);
    CHECK(merkle_build_with_layout(data, 0, 1, MERKLE_LAYOUT_FLAT, &bad)
          == MERKLE_INVALID_ARGUMENT);
    CHECK(merkle_build_with_layout(data, 3, 1, MERKLE_LAYOUT_FLAT, &bad)
          == MERKLE_INVALID_ARGUMENT);
    CHECK(merkle_build_with_layout(data, 1, 0, MERKLE_LAYOUT_FLAT, &bad)
          == MERKLE_INVALID_ARGUMENT);
    CHECK(merkle_build_with_layout(data, 1, 1, MERKLE_LAYOUT_FLAT, NULL)
          == MERKLE_INVALID_ARGUMENT);
    CHECK(merkle_build_with_layout(data, 2, SIZE_MAX, MERKLE_LAYOUT_FLAT, &bad)
          == MERKLE_SIZE_OVERFLOW);
    CHECK(merkle_build_with_layout(data, SIZE_MAX / 2 + 1, 1,
                                   MERKLE_LAYOUT_FLAT, &bad) == MERKLE_SIZE_OVERFLOW);
    /* Total nodes fit size_t, but their contiguous byte storage does not. */
    CHECK(merkle_build_with_layout(data, SIZE_MAX / 32 + 1, 1,
                                   MERKLE_LAYOUT_FLAT, &bad) == MERKLE_SIZE_OVERFLOW);
    CHECK(bad == NULL);
    CHECK(merkle_build(data, 0, 1, &bad) == MERKLE_INVALID_ARGUMENT);
    CHECK(merkle_build(data, 3, 1, &bad) == MERKLE_INVALID_ARGUMENT);
    CHECK(merkle_build(data, 1, 0, &bad) == MERKLE_INVALID_ARGUMENT);
    CHECK(merkle_build(data, 1, 1, NULL) == MERKLE_INVALID_ARGUMENT);
    CHECK(merkle_build(data, 2, SIZE_MAX, &bad) == MERKLE_SIZE_OVERFLOW);
    CHECK(merkle_build(data, SIZE_MAX / 2 + 1, 1, &bad)
          == MERKLE_SIZE_OVERFLOW);
    CHECK(bad == NULL);
    unsigned char digest[SHA256_DIGEST_BYTES];
    CHECK(sha256_digest(NULL, 1, digest) == -1);
    CHECK(sha256_digest(data, 1, NULL) == -1);
    if (SIZE_MAX > UINT64_MAX / 8) {
        CHECK(sha256_digest(data, SIZE_MAX, digest) == -1);
    }

    test_merkle_proofs();

    puts("C tests passed: SHA-256 vectors, tree structure, mutations, invalid inputs, proof generation, single verification.");
    return EXIT_SUCCESS;
}
