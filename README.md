
# Sequential pointer-based Merkle tree in C

This implements version A: a single-threaded, pointer-based binary Merkle
tree in C17. It is the correctness and performance reference for later
layout and parallelisation experiments.

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
./build/merkle_baseline 1024 256
```

The arguments are the number of leaves and bytes per input block. Without
a file argument, the program generates deterministic bytes with xorshift32,
seed 1. To hash your own binary input:

```sh
./build/merkle_baseline 4 32 input.bin
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

Every node is separately allocated with `malloc` and contains a 32-byte
digest plus left and right child pointers. Leaf child pointers are NULL.
All leaf hashes are computed first, followed by parents one level at a
time, on the calling thread. There are no worker threads or explicit SIMD
hash batches.

A temporary N-entry array of **pointers** tracks the current level and is
reused in place as the level shrinks. This is traversal workspace; the
nodes and their hashes still reside in separate allocations. The array is
freed before construction returns. The complete tree remains available
through child pointers, ready for future proof-generation work.

`merkle_build()` never retains the input buffer. Call `merkle_free()` to
release the result. Partial trees are also freed if an allocation or
OpenSSL hashing operation fails.
Cleanup uses recursion with depth proportional to log2(N).

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
overflow checks and every tree allocation and hash failure in a 16-leaf
construction. Failure injection covers the tree's cleanup paths, not
OpenSSL's internal allocations.
An independent Python implementation compares complete tree roots using
`hashlib.sha256`.

## Interpreting the output

`build_seconds` measures one call to `merkle_build()` using a monotonic
clock. It includes tree/workspace allocation, hashing, tree writes and
workspace release. It excludes input allocation/generation/file reading,
printing and final tree destruction. This is a smoke measurement, not the
proposal's full benchmark study; use warmups and repeated measurements
before reporting performance. The first build can also include OpenSSL's
lazy initialisation cost.

`node_storage_bytes` is `(2N - 1) * sizeof(MerkleNode)`.
`temporary_pointer_bytes` is `N * sizeof(MerkleNode *)`.
These are requested storage sizes, not measured process memory. They omit
allocator metadata, the tree wrapper, input buffer and stack. In particular,
per-node allocator overhead matters when comparing against contiguous
storage. Both variants should use the same timing boundaries.
=======
Hello World 123

前人栽Merkle-Tree，后人乘Top-Hash [^1]

# 前人栽Merkle-Tree，后人乘Top-Hash

## 前人栽Merkle-Tree，后人乘Top-Hash

### 前人栽Merkle-Tree，后人乘Top-Hash

**前人栽Merkle-Tree，后人乘Top-Hash**

*前人栽Merkle-Tree，后人乘Top-Hash*

> 前人栽Merkle-Tree，后人乘Top-Hash

`前人栽Merkle-Tree，后人乘Top-Hash`

---

[前人栽Merkle-Tree，后人乘Top-Hash](https://en.wikipedia.org/wiki/Merkle_tree)

1. 前人栽
2. Merkle-Tree
3. 后人乘
4. Top-Hash

- 前人栽Merkle-Tree，后人乘Top-Hash


| 前人栽 | 后人乘 |
| ---------- | ---------- |
| Merkle-Tree | Top-Hash |

前人栽Merkle-Tree
: 后人乘Top-Hash

- [x] 前人栽Merkle-Tree
- [ ] 后人乘Top-Hash :joy:

前人栽Merkle-Tree，==后人乘Top-Hash==

前人栽~Merkle-Tree~，后人乘^Top-Hash^

[^1]: 前人栽Merkle-Tree，后人乘Top-Hash 

