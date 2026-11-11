#!/bin/bash
# Proof generation / verification sweep (proposal Tasks 4-5, Section 4 grid).
#
#   scripts/run_proof_bench.sh            full grid (run via PBS on a compute node)
#   SMALL=1 scripts/run_proof_bench.sh    small representative run (~seconds)
#
# Output: results/proof_bench_<tag>.csv and results/proof_bench_<tag>.meta
set -euo pipefail

cd "$(dirname "$0")/.."

TAG=${TAG:-${PBS_JOBID:-$(date +%Y%m%d_%H%M%S)}}
TAG=${TAG%%.*}
OUT=results/proof_bench_${TAG}.csv
META=results/proof_bench_${TAG}.meta
mkdir -p results

# Physical cores, thread list, OMP affinity, write_meta
source scripts/bench_env.sh

if [[ "${SMALL:-0}" == 1 ]]; then
  LEAVES="1024 16384"; BLOCKS="32 256"; REPS=10; WARMUP=5
else
  LEAVES="1024 16384 262144 4194304"; BLOCKS="32 256 4096"; REPS=30; WARMUP=10
fi
BATCHES=1,8,32,128,512
SEED=1

# ---- Build and correctness check on this machine before timing ----
make -s bench build/test_merkle
./build/test_merkle

write_meta "$META" \
  "benchmark: proof generation / verification" \
  "seed: $SEED  reps: $REPS  warmup: $WARMUP  batches: $BATCHES" \
  "leaves: $LEAVES  blocks: $BLOCKS"

# ---- Sweep ----
# Verification never touches the tree, so its layout does not matter: verify
# runs on flat only. Proof generation walks the tree, so it runs on both.
header=--header
for leaves in $LEAVES; do
  for block in $BLOCKS; do
    common=(--leaves "$leaves" --block "$block" --batches "$BATCHES"
            --reps "$REPS" --warmup "$WARMUP" --seed "$SEED")
    echo "leaves=$leaves block=$block" >&2
    ./build/merkle_bench "${common[@]}" --layout flat --phase all \
        --threads "$THREADS" $header >> "$OUT"
    header=
    ./build/merkle_bench "${common[@]}" --layout pointer --phase gen >> "$OUT"
  done
done

echo "Wrote $OUT and $META" >&2
