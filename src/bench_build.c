/* Benchmark driver for Merkle tree construction (proposal Tasks 1-3).
 *
 * One invocation = one (layout, leaves, block size). Synthetic input is
 * generated once (untimed). Phases, in this order:
 *
 *   mem    one sequential build in a fresh process; reports the storage model
 *          (2N-1)*32, the node-structure bytes, the heap bytes actually in use
 *          (glibc mallinfo2, includes allocator headers/padding) and the RSS
 *          increase. Runs first so freed memory from other phases cannot be
 *          reused and hide the cost.
 *   alloc  allocation + first-touch cost alone, without hashing: 2N-1 node
 *          mallocs (pointer) or one (2N-1)*32-byte malloc + memset (flat).
 *   seq    merkle_build_with_layout (sequential builder).
 *   par    merkle_build_parallel at each thread count in --threads.
 *
 * Every timed phase runs --warmup untimed iterations then --reps timed ones,
 * one CSV row per timed iteration. Build time covers allocation, all hashing
 * and synchronisation; freeing the tree is timed separately (free_seconds).
 * Every root is compared with the first one (outside timing) so a wrong or
 * elided build fails the run.
 */
#define _GNU_SOURCE
#include "merkle.h"

#include <errno.h>
#include <inttypes.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_LIST 32

#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 33)
#define HAVE_MALLINFO2 1
#endif
#endif

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

static int parse_list(const char *text, size_t *out, size_t *count)
{
    if (text == NULL || strlen(text) >= 512) {
        return -1;
    }
    char buf[512];
    strcpy(buf, text);
    *count = 0;
    for (char *tok = strtok(buf, ","); tok != NULL; tok = strtok(NULL, ",")) {
        if (*count == MAX_LIST || parse_size(tok, &out[*count]) != 0
            || out[*count] == 0 || out[*count] > 4096) {
            return -1;
        }
        ++*count;
    }
    return *count == 0 ? -1 : 0;
}

static uint64_t rng_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

/* Resident set size in bytes (Linux /proc), or 0 if unavailable. */
static size_t rss_bytes(void)
{
    FILE *f = fopen("/proc/self/statm", "r");
    if (f == NULL) {
        return 0;
    }
    unsigned long size = 0, resident = 0;
    int n = fscanf(f, "%lu %lu", &size, &resident);
    fclose(f);
    return n == 2 ? (size_t)resident * (size_t)sysconf(_SC_PAGESIZE) : 0;
}

/* Heap bytes in use (arena + mmapped chunks), or 0 if unavailable. */
static size_t heap_bytes(void)
{
#ifdef HAVE_MALLINFO2
    struct mallinfo2 mi = mallinfo2();
    return mi.uordblks + mi.hblkhd;
#else
    return 0;
#endif
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --leaves N --block B [options]\n"
        "  --leaves N        leaf count (power of two)\n"
        "  --block B         bytes per leaf block\n"
        "  --layout L        pointer | flat                (default flat)\n"
        "  --phases LIST     subset of mem,alloc,seq,par   (default all)\n"
        "  --threads LIST    thread counts for par         (default 1,2,4)\n"
        "  --reps R          timed repetitions             (default 30)\n"
        "  --warmup W        untimed warmup iterations     (default 10)\n"
        "  --seed X          RNG seed for input data       (default 1)\n"
        "  --header          print the CSV header line first\n",
        prog);
}

typedef struct {
    const char *host;
    int openmp;
    const char *layout;
    size_t leaves, block, nodes;
} RowCtx;

static void print_row(const RowCtx *c, const char *phase, size_t threads,
                      size_t rep, double build_s, double free_s,
                      const char *mem_cols)
{
    double in_bytes = (double)c->leaves * (double)c->block;
    printf("%s,%d,%s,%s,%zu,%zu,%zu,%zu,%zu,%.9f,%.9f,%.3f,%.1f,%s\n",
           c->host, c->openmp, phase, c->layout, c->leaves, c->block, c->nodes,
           threads, rep, build_s, free_s, in_bytes / build_s / 1e6,
           (double)c->nodes / build_s, mem_cols);
}

int main(int argc, char **argv)
{
    size_t leaves = 0, block_size = 0, reps = 30, warmup = 10, seed = 1;
    size_t threads[MAX_LIST] = {1, 2, 4}, n_threads = 3;
    int do_mem = 1, do_alloc = 1, do_seq = 1, do_par = 1, header = 0;
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
        } else if (strcmp(a, "--threads") == 0) {
            bad = parse_list(v, threads, &n_threads);
        } else if (strcmp(a, "--phases") == 0 && v != NULL) {
            do_mem = strstr(v, "mem") != NULL;
            do_alloc = strstr(v, "alloc") != NULL;
            do_seq = strstr(v, "seq") != NULL;
            do_par = strstr(v, "par") != NULL;
            bad = !(do_mem || do_alloc || do_seq || do_par);
        } else if (strcmp(a, "--layout") == 0 && v != NULL) {
            if (strcmp(v, "flat") == 0) layout = MERKLE_LAYOUT_FLAT;
            else if (strcmp(v, "pointer") == 0) layout = MERKLE_LAYOUT_POINTER;
            else bad = 1;
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
        ++i;
    }
    if (leaves == 0 || block_size == 0 || (leaves & (leaves - 1)) != 0
        || leaves > SIZE_MAX / block_size) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* ---- Synthetic input (untimed) ---- */
    size_t input_bytes = leaves * block_size;
    unsigned char *data = malloc(input_bytes);
    if (data == NULL) {
        fprintf(stderr, "Unable to allocate %zu input bytes\n", input_bytes);
        return EXIT_FAILURE;
    }
    uint64_t rng = (seed + 1) * 0x9E3779B97F4A7C15ULL;
    size_t off = 0;
    for (; off + 8 <= input_bytes; off += 8) {
        uint64_t w = rng_next(&rng);
        memcpy(data + off, &w, 8);
    }
    for (; off < input_bytes; ++off) {
        data[off] = (unsigned char)rng_next(&rng);
    }

    char host[64] = "unknown";
    gethostname(host, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';
    size_t node_count = 2 * leaves - 1;
    size_t node_size = layout == MERKLE_LAYOUT_FLAT ? SHA256_DIGEST_BYTES
                                                    : sizeof(MerkleNode);
    RowCtx ctx = {
        .host = host,
#ifdef _OPENMP
        .openmp = 1,
#else
        .openmp = 0,
#endif
        .layout = layout == MERKLE_LAYOUT_FLAT ? "flat" : "pointer",
        .leaves = leaves, .block = block_size, .nodes = node_count,
    };
    if (header) {
        printf("host,openmp,phase,layout,leaves,block_bytes,nodes,threads,rep,"
               "seconds,free_seconds,input_mb_per_sec,nodes_per_sec,"
               "model_bytes,node_struct_bytes,heap_bytes,rss_delta_bytes\n");
    }
    const char *no_mem = ",,,";

    unsigned char ref_root[SHA256_DIGEST_BYTES];
    int have_ref = 0;
    MerkleTree *tree = NULL;
    MerkleStatus st;

    /* ---- mem: one build, measured before anything else touches the heap ---- */
    if (do_mem) {
        size_t rss0 = rss_bytes(), heap0 = heap_bytes();
        double t0 = now_seconds();
        st = merkle_build_with_layout(data, leaves, block_size, layout, &tree);
        double t1 = now_seconds();
        size_t rss1 = rss_bytes(), heap1 = heap_bytes();
        if (st != MERKLE_OK) {
            fprintf(stderr, "Build failed: %s\n", merkle_status_string(st));
            return EXIT_FAILURE;
        }
        memcpy(ref_root, merkle_root_hash(tree), SHA256_DIGEST_BYTES);
        have_ref = 1;
        double f0 = now_seconds();
        merkle_free(tree);
        double f1 = now_seconds();
        char heap_col[32] = "";   /* empty when mallinfo2 is unavailable */
#ifdef HAVE_MALLINFO2
        snprintf(heap_col, sizeof(heap_col), "%lld",
                 (long long)heap1 - (long long)heap0);
#else
        (void)heap0;
        (void)heap1;
#endif
        char cols[160];
        snprintf(cols, sizeof(cols), "%zu,%zu,%s,%lld",
                 node_count * SHA256_DIGEST_BYTES, node_count * node_size,
                 heap_col, (long long)rss1 - (long long)rss0);
        print_row(&ctx, "mem", 1, 0, t1 - t0, f1 - f0, cols);
        fflush(stdout);
    }

    /* ---- alloc: allocation + first touch only, no hashing ---- */
    if (do_alloc) {
        MerkleNode **nodes = NULL;
        if (layout == MERKLE_LAYOUT_POINTER) {
            nodes = malloc(node_count * sizeof(*nodes));
            if (nodes == NULL) {
                fprintf(stderr, "Allocation failed\n");
                return EXIT_FAILURE;
            }
        }
        for (size_t it = 0; it < warmup + reps; ++it) {
            double t0 = now_seconds(), t1, f0, f1;
            if (layout == MERKLE_LAYOUT_POINTER) {
                for (size_t i = 0; i < node_count; ++i) {
                    nodes[i] = malloc(sizeof(MerkleNode));
                    if (nodes[i] == NULL) {
                        fprintf(stderr, "Allocation failed\n");
                        return EXIT_FAILURE;
                    }
                    nodes[i]->left = NULL;   /* first touch, as the builder does */
                    nodes[i]->right = NULL;
                }
                t1 = now_seconds();
                f0 = t1;
                for (size_t i = 0; i < node_count; ++i) {
                    free(nodes[i]);
                }
                f1 = now_seconds();
            } else {
                unsigned char *buf = malloc(node_count * SHA256_DIGEST_BYTES);
                if (buf == NULL) {
                    fprintf(stderr, "Allocation failed\n");
                    return EXIT_FAILURE;
                }
                memset(buf, 0, node_count * SHA256_DIGEST_BYTES);
                t1 = now_seconds();
                /* keep the memset observable */
                volatile unsigned char sink = buf[node_count * SHA256_DIGEST_BYTES - 1];
                (void)sink;
                f0 = now_seconds();
                free(buf);
                f1 = now_seconds();
            }
            if (it >= warmup) {
                print_row(&ctx, "alloc", 1, it - warmup, t1 - t0, f1 - f0, no_mem);
            }
        }
        free(nodes);
        fflush(stdout);
    }

    /* ---- seq and par builds ---- */
    size_t n_cfg = (do_seq ? 1 : 0) + (do_par ? n_threads : 0);
    for (size_t c = 0; c < n_cfg; ++c) {
        int is_seq = do_seq && c == 0;
        size_t t = is_seq ? 1 : threads[c - (do_seq ? 1 : 0)];
        for (size_t it = 0; it < warmup + reps; ++it) {
            double t0 = now_seconds();
            st = is_seq
               ? merkle_build_with_layout(data, leaves, block_size, layout, &tree)
               : merkle_build_parallel(data, leaves, block_size, layout, (int)t, &tree);
            double t1 = now_seconds();
            if (st != MERKLE_OK) {
                fprintf(stderr, "Build failed: %s\n", merkle_status_string(st));
                return EXIT_FAILURE;
            }
            /* Correctness check outside timing; also defeats dead-code elimination. */
            if (!have_ref) {
                memcpy(ref_root, merkle_root_hash(tree), SHA256_DIGEST_BYTES);
                have_ref = 1;
            } else if (memcmp(ref_root, merkle_root_hash(tree), SHA256_DIGEST_BYTES) != 0) {
                fprintf(stderr, "Root mismatch (%s, %zu threads)\n",
                        is_seq ? "seq" : "par", t);
                return EXIT_FAILURE;
            }
            size_t actual = tree->build_threads;
            double f0 = now_seconds();
            merkle_free(tree);
            double f1 = now_seconds();
            if (!is_seq && actual != t) {
                fprintf(stderr, "warning: requested %zu threads, got %zu\n", t, actual);
            }
            if (it >= warmup) {
                print_row(&ctx, is_seq ? "seq" : "par", is_seq ? 1 : actual,
                          it - warmup, t1 - t0, f1 - f0, no_mem);
            }
        }
        fflush(stdout);
    }

    free(data);
    return EXIT_SUCCESS;
}
