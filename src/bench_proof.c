/* Benchmark driver for Merkle proof generation and (batched) verification.
 *
 * One invocation = one tree (layout, leaves, block size). Setup — synthetic
 * input, tree build (parallel builder, untimed), choice of leaf indices — is
 * done once. Then, for every batch size in --batches:
 *
 *   phase gen:     time sequential generation of `batch` proofs
 *                  (memory for proofs is freed outside the timed region)
 *   phase verify:  pre-generate `batch` proofs, then time
 *                  merkle_proof_verify_batch for the sequential baseline and
 *                  for each schedule x thread count in --scheds / --threads
 *
 * Each measured configuration runs --warmup untimed iterations followed by
 * --reps timed iterations; one CSV row is printed per timed iteration.
 * Single-proof latency = rows with phase=verify, batch=1, sched=seq.
 *
 * Note: merkle_proof_verify_batch takes its sequential path whenever
 * threads == 1, so static/dynamic at 1 thread equal the seq baseline.
 */
#define _POSIX_C_SOURCE 200809L
#include "merkle.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_LIST 32

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int parse_size(const char *text, size_t *value)
{
    if (text == NULL || *text < '0' || *text > '9') {
        return -1;
    }
    errno = 0;
    char *end;
    uintmax_t parsed = strtoumax(text, &end, 10);
    if (errno != 0 || *end != '\0' || parsed > SIZE_MAX) {
        return -1;
    }
    *value = (size_t)parsed;
    return 0;
}

/* Parse "1,8,32" into out[]; every value must be >= 1. */
static int parse_list(const char *text, size_t *out, size_t *count)
{
    if (text == NULL) {
        return -1;
    }
    char buf[512];
    if (strlen(text) >= sizeof(buf)) {
        return -1;
    }
    strcpy(buf, text);
    *count = 0;
    for (char *tok = strtok(buf, ","); tok != NULL; tok = strtok(NULL, ",")) {
        if (*count == MAX_LIST || parse_size(tok, &out[*count]) != 0
            || out[*count] == 0) {
            return -1;
        }
        ++*count;
    }
    return *count == 0 ? -1 : 0;
}

/* xorshift64: deterministic, cheap; not cryptographic. */
static uint64_t rng_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static uint64_t rng_seed(uint64_t seed, uint64_t stream)
{
    uint64_t s = (seed + 1) * 0x9E3779B97F4A7C15ULL ^ (stream + 1) * 0xBF58476D1CE4E5B9ULL;
    return s != 0 ? s : 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --leaves N --block B [options]\n"
        "  --leaves N         leaf count (power of two)\n"
        "  --block B          bytes per leaf block\n"
        "  --layout L         pointer | flat                 (default flat)\n"
        "  --phase P          gen | verify | all             (default all)\n"
        "  --batches LIST     proof batch sizes              (default 1,8,32,128,512)\n"
        "  --scheds LIST      static,dynamic subset          (default static,dynamic)\n"
        "  --threads LIST     thread counts for parallel     (default 1,2,4)\n"
        "  --reps R           timed repetitions              (default 30)\n"
        "  --warmup W         untimed warmup iterations      (default 5)\n"
        "  --seed X           RNG seed for data/indices      (default 1)\n"
        "  --header           print the CSV header line first\n",
        prog);
}

typedef struct {
    const char *host;
    int openmp;
    const char *layout;
    size_t leaves, block, depth;
} RowCtx;

typedef struct {
    MerkleBatchSchedule s;
    const char *name;
    size_t t;
} VerifyCfg;

static void print_row(const RowCtx *c, const char *phase, size_t batch,
                      const char *sched, size_t threads, size_t rep, double dt)
{
    printf("%s,%d,%s,%s,%zu,%zu,%zu,%zu,%s,%zu,%zu,%.9f,%.1f,%.1f\n",
           c->host, c->openmp, phase, c->layout, c->leaves, c->block, c->depth,
           batch, sched, threads, rep, dt, (double)batch / dt,
           dt * 1e9 / (double)batch);
}

int main(int argc, char **argv)
{
    size_t leaves = 0, block_size = 0, reps = 30, warmup = 5, seed = 1;
    size_t batches[MAX_LIST] = {1, 8, 32, 128, 512}, n_batches = 5;
    size_t threads[MAX_LIST] = {1, 2, 4}, n_threads = 3;
    int do_static = 1, do_dynamic = 1;
    int do_gen = 1, do_verify = 1, header = 0;
    MerkleLayout layout = MERKLE_LAYOUT_FLAT;

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        int bad = 0;
        if (strcmp(a, "--header") == 0) {
            header = 1;
            continue;
        } else if (strcmp(a, "--leaves") == 0) {
            bad = parse_size(v, &leaves);
        } else if (strcmp(a, "--block") == 0) {
            bad = parse_size(v, &block_size);
        } else if (strcmp(a, "--reps") == 0) {
            bad = parse_size(v, &reps) || reps == 0;
        } else if (strcmp(a, "--warmup") == 0) {
            bad = parse_size(v, &warmup);
        } else if (strcmp(a, "--seed") == 0) {
            bad = parse_size(v, &seed);
        } else if (strcmp(a, "--batches") == 0) {
            bad = parse_list(v, batches, &n_batches);
        } else if (strcmp(a, "--threads") == 0) {
            bad = parse_list(v, threads, &n_threads);
            for (size_t k = 0; !bad && k < n_threads; ++k) {
                bad = threads[k] > 4096;
            }
        } else if (strcmp(a, "--scheds") == 0 && v != NULL) {
            do_static = strstr(v, "static") != NULL;
            do_dynamic = strstr(v, "dynamic") != NULL;
            bad = !do_static && !do_dynamic;
        } else if (strcmp(a, "--layout") == 0 && v != NULL) {
            if (strcmp(v, "flat") == 0) layout = MERKLE_LAYOUT_FLAT;
            else if (strcmp(v, "pointer") == 0) layout = MERKLE_LAYOUT_POINTER;
            else bad = 1;
        } else if (strcmp(a, "--phase") == 0 && v != NULL) {
            do_gen = strcmp(v, "gen") == 0 || strcmp(v, "all") == 0;
            do_verify = strcmp(v, "verify") == 0 || strcmp(v, "all") == 0;
            bad = !do_gen && !do_verify;
        } else {
            fprintf(stderr, "Unknown or incomplete argument: %s\n", a);
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        if (bad) {
            fprintf(stderr, "Invalid value for %s\n", a);
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        ++i; /* consumed the value */
    }

    if (leaves == 0 || block_size == 0 || (leaves & (leaves - 1)) != 0
        || leaves > SIZE_MAX / block_size) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    size_t max_batch = 0;
    for (size_t k = 0; k < n_batches; ++k) {
        if (batches[k] > max_batch) max_batch = batches[k];
    }

    /* ---- Setup (untimed) ---- */
    size_t input_bytes = leaves * block_size;
    unsigned char *data = malloc(input_bytes);
    const void **blocks = malloc(max_batch * sizeof(*blocks));
    MerkleProof **proofs = calloc(max_batch, sizeof(*proofs));
    size_t *indices = malloc(max_batch * sizeof(*indices));
    int *results = malloc(max_batch * sizeof(*results));
    if (data == NULL || blocks == NULL || proofs == NULL
        || indices == NULL || results == NULL) {
        fprintf(stderr, "Allocation failed (input %zu bytes)\n", input_bytes);
        return EXIT_FAILURE;
    }

    uint64_t rng = rng_seed(seed, 0);
    size_t off = 0;
    for (; off + 8 <= input_bytes; off += 8) {
        uint64_t w = rng_next(&rng);
        memcpy(data + off, &w, 8);
    }
    for (; off < input_bytes; ++off) {
        data[off] = (unsigned char)rng_next(&rng);
    }

    /* The parallel builder produces an identical tree; it only speeds up setup. */
    MerkleTree *tree = NULL;
    MerkleStatus st = merkle_build_parallel(data, leaves, block_size, layout, 0, &tree);
    if (st != MERKLE_OK) {
        fprintf(stderr, "Build failed: %s\n", merkle_status_string(st));
        return EXIT_FAILURE;
    }
    const unsigned char *root = merkle_root_hash(tree);

    char host[64] = "unknown";
    gethostname(host, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';
    size_t depth = 0;
    while (((size_t)1 << depth) < leaves) ++depth;
    RowCtx ctx = {
        .host = host,
#ifdef _OPENMP
        .openmp = 1,
#else
        .openmp = 0,
#endif
        .layout = layout == MERKLE_LAYOUT_FLAT ? "flat" : "pointer",
        .leaves = leaves, .block = block_size, .depth = depth,
    };

    if (header) {
        printf("host,openmp,phase,layout,leaves,block_bytes,depth,batch,sched,"
               "threads,rep,seconds,proofs_per_sec,ns_per_proof\n");
    }
    const MerkleProof *const *cproofs = (const MerkleProof *const *)proofs;

    for (size_t b = 0; b < n_batches; ++b) {
        size_t batch = batches[b];
        /* Index set depends only on (seed, batch), not on layout or order of runs. */
        uint64_t irng = rng_seed(seed, batch);
        for (size_t i = 0; i < batch; ++i) {
            indices[i] = (size_t)(rng_next(&irng) & (leaves - 1));
            blocks[i] = data + indices[i] * block_size;
        }

        if (do_gen) {
            for (size_t it = 0; it < warmup + reps; ++it) {
                double t0 = now_seconds();
                for (size_t i = 0; i < batch; ++i) {
                    st = merkle_proof_generate(tree, indices[i], &proofs[i]);
                    if (st != MERKLE_OK) break;
                }
                double dt = now_seconds() - t0;
                if (st != MERKLE_OK) {
                    fprintf(stderr, "Proof generation failed: %s\n",
                            merkle_status_string(st));
                    return EXIT_FAILURE;
                }
                if (it >= warmup) {
                    print_row(&ctx, "gen", batch, "seq", 1, it - warmup, dt);
                }
                for (size_t i = 0; i < batch; ++i) {
                    merkle_proof_free(proofs[i]);
                    proofs[i] = NULL;
                }
            }
        }

        if (do_verify) {
            for (size_t i = 0; i < batch; ++i) {
                st = merkle_proof_generate(tree, indices[i], &proofs[i]);
                if (st != MERKLE_OK) {
                    fprintf(stderr, "Proof generation failed: %s\n",
                            merkle_status_string(st));
                    return EXIT_FAILURE;
                }
            }

            /* Configurations: seq baseline, then each schedule x thread count. */
            VerifyCfg cfg[1 + 2 * MAX_LIST];
            size_t n_cfg = 0;
            cfg[n_cfg++] = (VerifyCfg){MERKLE_SCHED_SEQUENTIAL, "seq", 1};
            for (size_t k = 0; k < n_threads; ++k) {
                if (do_static)
                    cfg[n_cfg++] = (VerifyCfg){MERKLE_SCHED_STATIC, "static", threads[k]};
                if (do_dynamic)
                    cfg[n_cfg++] = (VerifyCfg){MERKLE_SCHED_DYNAMIC, "dynamic", threads[k]};
            }

            for (size_t c = 0; c < n_cfg; ++c) {
                for (size_t it = 0; it < warmup + reps; ++it) {
                    double t0 = now_seconds();
                    int status = merkle_proof_verify_batch(
                        blocks, block_size, root, cproofs, batch,
                        cfg[c].s, (int)cfg[c].t, results);
                    double dt = now_seconds() - t0;
                    /* Result is checked (outside timing) so the work cannot be elided. */
                    if (status != 1) {
                        fprintf(stderr, "Verification failed (status %d)\n", status);
                        return EXIT_FAILURE;
                    }
                    if (it >= warmup) {
                        print_row(&ctx, "verify", batch, cfg[c].name, cfg[c].t,
                                  it - warmup, dt);
                    }
                }
            }
            for (size_t i = 0; i < batch; ++i) {
                merkle_proof_free(proofs[i]);
                proofs[i] = NULL;
            }
        }
        fflush(stdout);
    }

    merkle_free(tree);
    free(results);
    free(indices);
    free(proofs);
    free(blocks);
    free(data);
    return EXIT_SUCCESS;
}
