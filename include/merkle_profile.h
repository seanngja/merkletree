#ifndef MERKLE_PROFILE_H
#define MERKLE_PROFILE_H

/* Per-level timing for the parallel flat builder (proposal Section 4:
 * "time breakdown for leaf hashing, internal-node hashing and synchronisation"
 * and "per-level timing ... showing how parallelism decreases toward the root").
 *
 * Only available when src/merkle.c is compiled with -DMERKLE_PROFILE (and
 * OpenMP). Normal builds contain none of this code. In a profiled build each
 * worksharing level ends with `nowait` + an explicit barrier instead of the
 * implicit barrier, so each thread's finish time can be recorded before it
 * waits; the synchronisation semantics are unchanged.
 *
 * Times are omp_get_wtime() seconds, recorded by each thread for itself.
 * For parallel level k (k = 0 is leaves) and thread t:
 *   thread_start[k][t]   t begins level k (leaves the previous barrier)
 *   thread_done[k][t]    t has finished its share of level k
 *   busy = thread_done[k][t] - thread_start[k][t]
 *   wait = thread_start[k+1][t] - thread_done[k][t]   (barrier: sync + imbalance)
 * thread_start[levels][t] is when t leaves the last parallel barrier. Levels
 * too narrow for the team then run on one thread between tail_start and
 * tail_end ("tail").
 */

#include <stddef.h>

#define MERKLE_PROF_MAX_THREADS 256
#define MERKLE_PROF_MAX_LEVELS 65

typedef struct {
    int team;                   /* threads in the team */
    size_t levels;              /* parallel levels recorded, leaves included */
    size_t nodes[MERKLE_PROF_MAX_LEVELS];       /* hashes computed per level */
    double start;               /* thread 0, all threads in region, before leaves */
    double thread_start[MERKLE_PROF_MAX_LEVELS + 1][MERKLE_PROF_MAX_THREADS];
    double thread_done[MERKLE_PROF_MAX_LEVELS][MERKLE_PROF_MAX_THREADS];
    size_t tail_levels;         /* levels run on one thread at the top */
    size_t tail_nodes;          /* hashes computed in the tail */
    double tail_start, tail_end;
    double end;                 /* after the parallel region has joined */
} MerkleBuildProfile;

/* Profile of the most recent merkle_build_parallel(..., MERKLE_LAYOUT_FLAT, ...). */
const MerkleBuildProfile *merkle_build_profile(void);

#endif
