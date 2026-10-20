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
    puts("C tests passed: SHA-256 vectors, tree structure, mutations, invalid inputs.");
    return EXIT_SUCCESS;
}
