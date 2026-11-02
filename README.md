# Sequential Merkle trees in C

This implements versions A and B: single-threaded binary Merkle trees in
C17 with selectable pointer-based or contiguous flat storage. Both use the
same OpenSSL SHA-256 primitive and tree semantics.

## Build and run

Requires a C17 compiler, Make and OpenSSL development headers/libraries
on a POSIX system. On Ubuntu/Debian, install the dependency with:

```sh
sudo apt-get install libssl-dev
```

The build links OpenSSL's crypto library with `-lcrypto`.
It also detects development files extracted under `.deps/usr`; that
directory is ignored by version control. This workspace uses local headers
from `libssl-dev` 3.0.13-0ubuntu3.16 and the matching installed system
`libcrypto.so.3`. The local library directory contains a symlink to that
runtime. A system-wide development package is therefore unnecessary here.
On another machine, install `libssl-dev` as above, or supply a complete
development prefix with `make OPENSSL_PREFIX=/path/to/openssl`.

```sh
make
./build/merkle_baseline 1024 256                         # default: pointer
./build/merkle_baseline --layout pointer 1024 256
./build/merkle_baseline --layout flat 1024 256
```

Use `--layout pointer` or `--layout flat` to select storage without rebuilding.
The option can appear before or after the positional arguments.
The positional arguments are the number of leaves and bytes per input block. Without
a file argument, the program generates deterministic bytes with xorshift32,
seed 1. To hash your own binary input:

```sh
./build/merkle_baseline --layout flat 4 32 input.bin
```

The file must contain exactly `LEAVES * BLOCK_BYTES` bytes (128 in this
example). Leaf counts must be positive powers of two; block sizes must be
positive. Unsupported sizes, short/long files and allocation failures
produce an error and a nonzero exit code.

## Tree semantics and storage

- A leaf contains `SHA256(block)`.
- A parent contains `SHA256(left_hash || right_hash)`, concatenating the
  two raw 32-byte digests, not their hexadecimal strings.
- Input order determines left/right order. No prefixes, sorting or
  duplicate-last padding are added.
- A one-leaf tree's root is simply the leaf digest.
- A tree with N leaves has N - 1 internal nodes and 2N - 1 total nodes.

In pointer layout, every node is separately allocated with `malloc` and contains a 32-byte
digest plus left and right child pointers. Leaf child pointers are NULL.
All leaf hashes are computed first, followed by parents one level at a
time, on the calling thread. There are no worker threads or explicit SIMD
hash batches.

A temporary N-entry array of **pointers** tracks the current level and is
reused in place as the level shrinks. This is traversal workspace; the
nodes and their hashes still reside in separate allocations. The array is
freed before construction returns. The complete tree remains available
through child pointers, ready for future proof-generation work.

In flat layout, a single buffer contains all `(2N - 1)` hashes, with no child
pointers or temporary pointer array. For eight leaves the node indices are:

```text
Leaves:       0  1  2  3  4  5  6  7
Parents:      8  9 10 11
Next level:  12 13
Root:        14
```

For a level starting at offset `o` with width `w`, parent `i` is stored at
`o + w + i`; its children are at `o + 2*i` and `o + 2*i + 1`.
Each index addresses a 32-byte hash. All levels are retained.

The original `merkle_build()` API still builds pointer trees. Use the new
API to select either representation:

```c
MerkleTree *tree = NULL;
MerkleStatus status = merkle_build_with_layout(data, 1024, 256,
                                              MERKLE_LAYOUT_FLAT, &tree);
if (status == MERKLE_OK) {
    const unsigned char *root = merkle_root_hash(tree); /* 32 bytes */
    /* Use root before freeing the tree. */
    (void)root;
}
merkle_free(tree);
```

`merkle_root_hash()` works for either layout. `tree->root` is only populated
for pointer trees; flat trees use `tree->flat_hashes`, with the root stored
last. Both constructors leave the input buffer owned by the caller and do
not retain it. Call `merkle_free()` to release either representation. Partial trees are also freed if an allocation or
OpenSSL hashing operation fails.
Pointer cleanup uses recursion with depth proportional to log2(N); flat
cleanup frees its one hash buffer.

## Source map

| File | Purpose |
| --- | --- |
| `include/merkle.h` | Public node/tree types, construction and cleanup API |
| `src/merkle.c` | Sequential leaf hashing, level reduction and ownership |
| `src/sha256.c` | Small wrapper around OpenSSL's EVP SHA-256 interface |
| `src/main.c` | Synthetic/file input, single-build timing and root output |
| `tests/` | Hash vectors, structure checks, allocation failures and independent roots |

SHA-256 is provided by OpenSSL through
[`EVP_Digest()` and `EVP_sha256()`](https://docs.openssl.org/3.0/man3/EVP_DigestInit/).
There is no handwritten SHA-256 algorithm in this project. Tree construction
remains single-threaded; OpenSSL can use CPU-specific hash acceleration.
Use the same OpenSSL version/configuration and compiler settings across
variants when comparing memory layout or threading. Record `openssl version`
with benchmark results. Python `hashlib` provides a separate tree oracle,
although it may use the same underlying OpenSSL library.

## Validation

```sh
make test
make sanitize
```

Tests require Python 3; allocation/hash-failure tests use GNU-compatible linker
`--wrap` support. The sanitizer target uses GCC-compatible AddressSanitizer
and UndefinedBehaviorSanitizer flags in a separate build directory.

Tests cover known SHA-256 vectors (including the empty message and one
million `a` bytes), one/two/many-leaf trees, repeated leaves, changed input,
ordering, block sizes around SHA-256 padding boundaries, invalid inputs,
overflow checks, exact level ordering in flat storage, and every tree
allocation and hash failure in a 16-leaf construction for both layouts. Failure injection covers the tree's cleanup paths, not
OpenSSL's internal allocations.
An independent Python implementation compares complete tree roots using
`hashlib.sha256`.

## Interpreting the output

`build_seconds` measures one call to `merkle_build_with_layout()` using a monotonic
clock. It includes tree/workspace allocation, hashing, tree writes and
workspace release. It excludes input allocation/generation/file reading,
printing and final tree destruction. This is a smoke measurement, not the
proposal's full benchmark study; use warmups and repeated measurements
before reporting performance. The first build can also include OpenSSL's
lazy initialisation cost.

The output identifies `variant=sequential_pointer` or `variant=sequential_flat`.
For pointer layout, `node_storage_bytes` is `(2N - 1) * sizeof(MerkleNode)`
and `temporary_pointer_bytes` is `N * sizeof(MerkleNode *)`.
For flat layout, these are `(2N - 1) * 32` and `0`, respectively.
These are requested storage sizes, not measured process memory. They omit
allocator metadata, the tree wrapper, input buffer and stack. In particular,
per-node allocator overhead matters when comparing against contiguous
storage. Both variants should use the same timing boundaries.
