/* Per-level timing of the parallel flat builder.
 *
 * Links against a copy of merkle.c compiled with -DMERKLE_PROFILE (see the
 * Makefile target build/merkle_bench_levels). For each thread count, runs
 * --warmup untimed and --reps timed builds and prints, per timed build, one
 * row per tree level plus a "tail" row (narrow top levels done on one thread)
 * and a "total" row.
 *
 * Columns per level (seconds, each thread timed on its own clock readings):
 *   seconds          mean per-thread time in the level (busy + wait)
 *   busy_min/mean/max  per-thread time spent hashing before reaching the barrier
 *   wait_mean/max    per-thread barrier wait until release (sync + imbalance)
 * Total row: seconds = whole build; busy_* = sum over levels of busy_mean;
 * wait_mean = sum of per-level wait_mean (synchronisation estimate).
 *
 * The profiled build adds an omp_get_wtime() per thread per level and two
 * barriers at region start; use merkle_bench_build for headline timings.
 */
#define _POSIX_C_SOURCE 200809L
#include "merkle.h"
#include "merkle_profile.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_LIST 32

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
            || out[*count] == 0 || out[*count] > MERKLE_PROF_MAX_THREADS) {
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

int main(int argc, char **argv)
{
    size_t leaves = 0, block_size = 0, reps = 10, warmup = 2, seed = 1;
    size_t threads[MAX_LIST] = {1, 2, 4}, n_threads = 3;
    int header = 0;

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        int bad = 0;
        if (strcmp(a, "--header") == 0) { header = 1; continue; }
        else if (strcmp(a, "--leaves") == 0) bad = parse_size(v, &leaves);
        else if (strcmp(a, "--block") == 0) bad = parse_size(v, &block_size);
        else if (strcmp(a, "--reps") == 0) bad = parse_size(v, &reps) || reps == 0;
        else if (strcmp(a, "--warmup") == 0) bad = parse_size(v, &warmup);
        else if (strcmp(a, "--seed") == 0) bad = parse_size(v, &seed);
        else if (strcmp(a, "--threads") == 0) bad = parse_list(v, threads, &n_threads);
        else {
            fprintf(stderr,
                    "Usage: %s --leaves N --block B [--threads LIST] [--reps R]"
                    " [--warmup W] [--seed X] [--header]\n", argv[0]);
            return EXIT_FAILURE;
        }
        if (bad) {
            fprintf(stderr, "Invalid value for %s\n", a);
            return EXIT_FAILURE;
        }
        ++i;
    }
    if (leaves < 2 || block_size == 0 || (leaves & (leaves - 1)) != 0
        || leaves > SIZE_MAX / block_size) {
        fprintf(stderr, "--leaves must be a power of two >= 2, --block >= 1\n");
        return EXIT_FAILURE;
    }

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

    if (header) {
        printf("host,leaves,block_bytes,threads,rep,level,kind,nodes,seconds,"
               "busy_min,busy_mean,busy_max,wait_mean,wait_max\n");
    }

    unsigned char ref_root[SHA256_DIGEST_BYTES];
    int have_ref = 0;

    for (size_t c = 0; c < n_threads; ++c) {
        for (size_t it = 0; it < warmup + reps; ++it) {
            MerkleTree *tree = NULL;
            MerkleStatus st = merkle_build_parallel(data, leaves, block_size,
                                                    MERKLE_LAYOUT_FLAT,
                                                    (int)threads[c], &tree);
            if (st != MERKLE_OK) {
                fprintf(stderr, "Build failed: %s\n", merkle_status_string(st));
                return EXIT_FAILURE;
            }
            if (!have_ref) {
                memcpy(ref_root, merkle_root_hash(tree), SHA256_DIGEST_BYTES);
                have_ref = 1;
            } else if (memcmp(ref_root, merkle_root_hash(tree), SHA256_DIGEST_BYTES) != 0) {
                fprintf(stderr, "Root mismatch at %zu threads\n", threads[c]);
                return EXIT_FAILURE;
            }
            merkle_free(tree);
            if (it < warmup) {
                continue;
            }

            const MerkleBuildProfile *p = merkle_build_profile();
            size_t team = (size_t)p->team;
            size_t rep = it - warmup;
            double sum_busy = 0.0, sum_wait = 0.0;
            for (size_t l = 0; l < p->levels; ++l) {
                double bmin = 1e30, bmax = 0.0, bsum = 0.0, wmax = 0.0, wsum = 0.0;
                double ssum = 0.0;
                for (size_t t = 0; t < team; ++t) {
                    double busy = p->thread_done[l][t] - p->thread_start[l][t];
                    double wait = p->thread_start[l + 1][t] - p->thread_done[l][t];
                    if (busy < bmin) bmin = busy;
                    if (busy > bmax) bmax = busy;
                    if (wait > wmax) wmax = wait;
                    bsum += busy;
                    wsum += wait;
                    ssum += p->thread_start[l + 1][t] - p->thread_start[l][t];
                }
                double bmean = bsum / (double)team, wmean = wsum / (double)team;
                sum_busy += bmean;
                sum_wait += wmean;
                /* seconds: per-thread time spent in this level (busy + wait), averaged */
                printf("%s,%zu,%zu,%zu,%zu,%zu,%s,%zu,%.9f,%.9f,%.9f,%.9f,%.9f,%.9f\n",
                       host, leaves, block_size, team, rep, l,
                       l == 0 ? "leaf" : "internal", p->nodes[l],
                       ssum / (double)team, bmin, bmean, bmax, wmean, wmax);
            }
            double tail = p->tail_end - p->tail_start;
            printf("%s,%zu,%zu,%zu,%zu,%zu,tail,%zu,%.9f,%.9f,%.9f,%.9f,,\n",
                   host, leaves, block_size, team, rep, p->levels, p->tail_nodes,
                   tail, tail, tail, tail);
            printf("%s,%zu,%zu,%zu,%zu,,total,%zu,%.9f,,%.9f,,%.9f,\n",
                   host, leaves, block_size, team, rep, 2 * leaves - 1,
                   p->end - p->start, sum_busy + tail, sum_wait);
        }
        fflush(stdout);
    }
    free(data);
    return EXIT_SUCCESS;
}
