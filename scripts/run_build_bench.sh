#!/bin/bash
# Tree construction sweep (proposal Tasks 1-3, Section 4 grid).
#
#   scripts/run_build_bench.sh            full grid (run via PBS on a compute node)
#   SMALL=1 scripts/run_build_bench.sh    small representative run (~seconds)
#
# Output:
#   results/build_bench_<tag>.csv    mem / alloc / seq / par rows (merkle_bench_build)
#   results/build_levels_<tag>.csv   per-level timing (merkle_bench_levels, flat parallel)
#   results/build_bench_<tag>.meta   machine and configuration record
set -euo pipefail

cd "$(dirname "$0")/.."

TAG=${TAG:-${PBS_JOBID:-$(date +%Y%m%d_%H%M%S)}}
TAG=${TAG%%.*}
OUT=results/build_bench_${TAG}.csv
LEVELS_OUT=results/build_levels_${TAG}.csv
META=results/build_bench_${TAG}.meta
mkdir -p results

source scripts/bench_env.sh

if [[ "${SMALL:-0}" == 1 ]]; then
  LEAVES="1024 16384"; BLOCKS="32 256"
  LEVEL_LEAVES="16384"; LEVEL_BLOCKS="32"
  REPS=10; WARMUP=5; BIG_REPS=10; BIG_WARMUP=5
else
  LEAVES="1024 16384 262144 4194304"; BLOCKS="32 256 4096"
  # Per-level evidence for two contrasting tree sizes and leaf costs.
  LEVEL_LEAVES="16384 4194304"; LEVEL_BLOCKS="32 4096"
  REPS=30; WARMUP=10
  # Inputs >= 256 MiB (up to 16 GiB) take seconds to minutes per build and do
  # not fit in any cache, so fewer warmups/repeats are used there.
  BIG_REPS=10; BIG_WARMUP=2
fi
BIG_BYTES=$((256 * 1024 * 1024))
SEED=1

reps_for() {  # leaves block -> "reps warmup"
  if (( $1 * $2 >= BIG_BYTES )); then echo "$BIG_REPS $BIG_WARMUP"; else echo "$REPS $WARMUP"; fi
}

# ---- Build and correctness check on this machine before timing ----
make -s bench build/test_merkle
./build/test_merkle

write_meta "$META" \
  "benchmark: tree construction" \
  "seed: $SEED  reps: $REPS  warmup: $WARMUP  (inputs >= 256 MiB: reps $BIG_REPS warmup $BIG_WARMUP)" \
  "leaves: $LEAVES  blocks: $BLOCKS" \
  "levels: leaves $LEVEL_LEAVES  blocks $LEVEL_BLOCKS (flat parallel, profiled build)"

# ---- Construction: both layouts, sequential + parallel, memory + allocation ----
# Each (leaves, block, layout) runs in a fresh process so the mem phase sees
# an untouched heap.
header=--header
for leaves in $LEAVES; do
  for block in $BLOCKS; do
    read -r reps warmup <<< "$(reps_for "$leaves" "$block")"
    for layout in flat pointer; do
      echo "build: leaves=$leaves block=$block layout=$layout" >&2
      ./build/merkle_bench_build --leaves "$leaves" --block "$block" \
          --layout "$layout" --threads "$THREADS" --reps "$reps" \
          --warmup "$warmup" --seed "$SEED" $header >> "$OUT"
      header=
    done
  done
done

# ---- Per-level timing (flat parallel builder, instrumented) ----
header=--header
for leaves in $LEVEL_LEAVES; do
  for block in $LEVEL_BLOCKS; do
    read -r reps warmup <<< "$(reps_for "$leaves" "$block")"
    echo "levels: leaves=$leaves block=$block" >&2
    ./build/merkle_bench_levels --leaves "$leaves" --block "$block" \
        --threads "$THREADS" --reps "$reps" --warmup "$warmup" \
        --seed "$SEED" $header >> "$LEVELS_OUT"
    header=
  done
done

echo "Wrote $OUT, $LEVELS_OUT and $META" >&2
