# Shared setup for benchmark sweeps; source from run_*_bench.sh.
#
# Sets: PHYS (physical cores this process may use, SMT siblings excluded),
#       THREADS (1,2,4,... <= PHYS, plus PHYS), ALLOWED_CPUS,
#       OMP_PROC_BIND / OMP_PLACES (exported).
# Defines: write_meta FILE "extra lines..."

ALLOWED_CPUS=$(awk '/Cpus_allowed_list/{print $2}' /proc/self/status)
_phys=$(
  for range in ${ALLOWED_CPUS//,/ }; do
    lo=${range%-*}; hi=${range#*-}
    for ((c = lo; c <= hi; c++)); do
      t=/sys/devices/system/cpu/cpu$c/topology
      echo "$(cat "$t/physical_package_id"):$(cat "$t/core_id")"
    done
  done | sort -u | wc -l
)
PHYS=${PHYS:-$_phys}

THREADS=""
for ((t = 1; t <= PHYS; t *= 2)); do THREADS+="${THREADS:+,}$t"; done
[[ ",$THREADS," == *",$PHYS,"* ]] || THREADS+=",$PHYS"

export OMP_PROC_BIND=${OMP_PROC_BIND:-close}
export OMP_PLACES=${OMP_PLACES:-cores}

# Environment record (proposal Section 4: CPU model, caches, cores,
# compiler/flags, thread affinity, hash implementation).
write_meta() {
  local file=$1; shift
  {
    echo "date: $(date -Is)"
    echo "host: $(hostname)"
    echo "pbs_jobid: ${PBS_JOBID:-none}"
    echo "pbs_ncpus: ${NCPUS:-none}"
    echo "allowed_cpus: $ALLOWED_CPUS"
    echo "physical_cores_used: $PHYS"
    echo "threads_swept: $THREADS"
    echo "OMP_PROC_BIND=$OMP_PROC_BIND OMP_PLACES=$OMP_PLACES"
    echo "compile: $(make -s print-flags)"
    echo "compiler: $(command -v ${CC:-cc}) $(${CC:-cc} --version | head -1)"
    echo "glibc: $(ldd --version 2>/dev/null | head -1)"
    echo "hash: SHA-256, in-tree implementation src/sha256.c (no external library)"
    for line in "$@"; do echo "$line"; done
    echo "--- lscpu ---"
    lscpu
    echo "--- cache (lscpu -C) ---"
    lscpu -C 2>/dev/null || true
    echo "--- memory ---"
    free -g 2>/dev/null || true
  } > "$file"
}
