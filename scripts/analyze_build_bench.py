#!/usr/bin/env python3
"""Summarise construction benchmark CSVs (proposal Tasks 1-3, Section 4).

    python3 scripts/analyze_build_bench.py results/build_bench_<tag>.csv \
        [--levels results/build_levels_<tag>.csv] [--plots DIR]

Writes next to the input:
    <build>.summary.csv     median / IQR / throughput / speedup / scaling
    <build>.memory.csv      storage model vs measured memory, per layout
    <levels>.summary.csv    per-level medians and the leaf/internal/sync breakdown

Definitions:
    speedup  = T_seq / T_par            (same layout, N, leaf size)
    scaling  = T_par(1 thread) / T_par(p threads)
    flat_vs_pointer = T_pointer / T_flat (same phase, threads, N, leaf size)
"""
import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def quart(xs):
    xs = sorted(xs)
    if len(xs) < 2:
        return xs[0], xs[0], xs[0]
    q1, med, q3 = statistics.quantiles(xs, n=4, method="inclusive")
    return q1, med, q3


def log2(n):
    return n.bit_length() - 1


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, cols, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        w.writerows(rows)


# ---------------------------------------------------------------- build ----
def summarise_build(rows):
    groups = defaultdict(lambda: ([], []))
    for r in rows:
        if r["phase"] == "mem":
            continue
        key = (r["phase"], r["layout"], int(r["leaves"]), int(r["block_bytes"]),
               int(r["threads"]))
        groups[key][0].append(float(r["seconds"]))
        groups[key][1].append(float(r["free_seconds"]))

    s = {}
    for key, (secs, frees) in groups.items():
        q1, med, q3 = quart(secs)
        _, leaves, block = key[1], key[2], key[3]
        s[key] = dict(n=len(secs), median_s=med, q1_s=q1, q3_s=q3, iqr_s=q3 - q1,
                      free_median_s=statistics.median(frees),
                      input_mb_per_s=leaves * block / med / 1e6,
                      nodes_per_s=(2 * leaves - 1) / med)
    for key, v in s.items():
        phase, layout, leaves, block, threads = key
        seq = s.get(("seq", layout, leaves, block, 1))
        p1 = s.get(("par", layout, leaves, block, 1))
        other = s.get((phase, "pointer" if layout == "flat" else "flat",
                       leaves, block, threads))
        v["speedup_vs_seq"] = seq["median_s"] / v["median_s"] if seq and phase == "par" else ""
        v["scaling_T1_over_Tp"] = p1["median_s"] / v["median_s"] if p1 and phase == "par" else ""
        v["pointer_over_flat"] = (
            (v["median_s"] / other["median_s"] if layout == "pointer" else other["median_s"] / v["median_s"])
            if other else "")
    return s


def memory_table(rows):
    out = []
    for r in rows:
        if r["phase"] != "mem":
            continue
        model = int(r["model_bytes"])
        heap = int(r["heap_bytes"]) if r["heap_bytes"] else None
        rss = int(r["rss_delta_bytes"])
        out.append([r["layout"], int(r["leaves"]), int(r["block_bytes"]), model,
                    int(r["node_struct_bytes"]), heap if heap is not None else "", rss,
                    round(heap / model, 3) if heap else "", round(rss / model, 3),
                    float(r["seconds"]), float(r["free_seconds"])])
    out.sort(key=lambda x: (x[1], x[2], x[0]))
    return out


def print_build(s, mem):
    print("\nSequential construction, median [IQR] ms and input MB/s:")
    for key in sorted(k for k in s if k[0] == "seq"):
        v = s[key]
        print(f"  {key[1]:<7} N=2^{log2(key[2]):<2} leaf={key[3]:>4}B  "
              f"{v['median_s'] * 1e3:10.3f} [{v['iqr_s'] * 1e3:.3f}]  "
              f"{v['input_mb_per_s']:8.1f} MB/s  "
              f"pointer/flat={v['pointer_over_flat']:.3f}" if v['pointer_over_flat'] != "" else "")

    print("\nAllocation + first touch as a share of the sequential build:")
    for key in sorted(k for k in s if k[0] == "alloc"):
        seq = s.get(("seq",) + key[1:])
        if seq:
            print(f"  {key[1]:<7} N=2^{log2(key[2]):<2} leaf={key[3]:>4}B  "
                  f"alloc {s[key]['median_s'] * 1e3:9.3f} ms = "
                  f"{100 * s[key]['median_s'] / seq['median_s']:5.1f}%   "
                  f"free {seq['free_median_s'] * 1e3:8.3f} ms")

    print("\nMemory: model (2N-1)*32 vs measured (heap = allocator view, rss = pages touched):")
    for m in mem:
        print(f"  {m[0]:<7} N=2^{log2(m[1]):<2} leaf={m[2]:>4}B  model {m[3] / 2**20:9.2f} MiB  "
              f"struct {m[4] / 2**20:9.2f}  heap {m[5] / 2**20 if m[5] != '' else float('nan'):9.2f}  "
              f"rss {m[6] / 2**20:9.2f}  heap/model {m[7] or '-'}")

    print("\nParallel speedup vs sequential at max threads:")
    for layout in ("flat", "pointer"):
        par = [k for k in s if k[0] == "par" and k[1] == layout]
        if not par:
            continue
        tmax = max(k[4] for k in par)
        for key in sorted(k for k in par if k[4] == tmax):
            v = s[key]
            print(f"  {layout:<7} N=2^{log2(key[2]):<2} leaf={key[3]:>4}B  {tmax:>3} threads  "
                  f"speedup {v['speedup_vs_seq']:6.2f}x  scaling {v['scaling_T1_over_Tp']:6.2f}x  "
                  f"efficiency {v['scaling_T1_over_Tp'] / tmax:5.2f}")


# --------------------------------------------------------------- levels ----
def summarise_levels(rows):
    per_level = defaultdict(lambda: defaultdict(list))
    for r in rows:
        key = (int(r["leaves"]), int(r["block_bytes"]), int(r["threads"]),
               r["level"], r["kind"], int(r["nodes"]))
        for col in ("seconds", "busy_min", "busy_mean", "busy_max", "wait_mean", "wait_max"):
            if r[col] != "":
                per_level[key][col].append(float(r[col]))
    med = {k: {c: statistics.median(v) for c, v in cols.items()} for k, cols in per_level.items()}

    breakdown = defaultdict(lambda: dict(leaf=0.0, internal=0.0, tail=0.0, sync=0.0, total=0.0))
    for (leaves, block, threads, level, kind, nodes), v in med.items():
        b = breakdown[(leaves, block, threads)]
        if kind == "leaf":
            b["leaf"] += v["busy_mean"]
            b["sync"] += v["wait_mean"]
        elif kind == "internal":
            b["internal"] += v["busy_mean"]
            b["sync"] += v["wait_mean"]
        elif kind == "tail":
            b["tail"] += v["seconds"]
        elif kind == "total":
            b["total"] = v["seconds"]
    return med, breakdown


def print_levels(med, breakdown):
    print("\nTime breakdown (flat parallel, medians, % of total build):")
    for key in sorted(breakdown):
        b = breakdown[key]
        t = b["total"] or 1.0
        print(f"  N=2^{log2(key[0]):<2} leaf={key[1]:>4}B {key[2]:>3} thr  total {t * 1e3:9.3f} ms  "
              f"leaf {100 * b['leaf'] / t:5.1f}%  internal {100 * b['internal'] / t:5.1f}%  "
              f"tail {100 * b['tail'] / t:5.1f}%  sync/imbalance {100 * b['sync'] / t:5.1f}%")


def level_rows(med):
    out = []
    for key in sorted(med, key=lambda k: (k[0], k[1], k[2], k[3] == "", int(k[3] or 0))):
        leaves, block, threads, level, kind, nodes = key
        v = med[key]
        wait_frac = (v["wait_mean"] / v["seconds"]) if "wait_mean" in v and v["seconds"] else ""
        imbalance = (v["busy_max"] - v["busy_min"]) if "busy_max" in v and "busy_min" in v else ""
        out.append([leaves, block, threads, level, kind, nodes, v.get("seconds", ""),
                    v.get("busy_mean", ""), v.get("wait_mean", ""), imbalance, wait_frac,
                    nodes / threads if kind in ("leaf", "internal") else ""])
    return out


# ---------------------------------------------------------------- plots ----
def plots(s, med, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plots", file=sys.stderr)
        return
    outdir.mkdir(parents=True, exist_ok=True)

    # Thread scaling per layout, one line per (N, leaf)
    for layout in ("flat", "pointer"):
        fig, ax = plt.subplots(figsize=(6, 4))
        for leaves, block in sorted({(k[2], k[3]) for k in s if k[0] == "par" and k[1] == layout}):
            pts = sorted((k[4], v["scaling_T1_over_Tp"]) for k, v in s.items()
                         if k[0] == "par" and k[1:4] == (layout, leaves, block))
            ax.plot(*zip(*pts), marker="o", label=f"N=2^{log2(leaves)} {block}B")
        tmax = max((k[4] for k in s if k[0] == "par"), default=1)
        ax.plot([1, tmax], [1, tmax], "k:", label="ideal")
        ax.set_xlabel("threads"); ax.set_ylabel("T1 / Tp")
        ax.set_title(f"Construction thread scaling ({layout})")
        ax.legend(fontsize=6, ncol=2)
        fig.tight_layout(); fig.savefig(outdir / f"build_scaling_{layout}.png", dpi=150)
        plt.close(fig)

    # Sequential throughput vs N, per leaf size and layout
    fig, ax = plt.subplots(figsize=(6, 4))
    for layout in ("flat", "pointer"):
        for block in sorted({k[3] for k in s if k[0] == "seq"}):
            pts = sorted((k[2], v["input_mb_per_s"]) for k, v in s.items()
                         if k[0] == "seq" and k[1] == layout and k[3] == block)
            if pts:
                ax.plot(*zip(*pts), marker="o", linestyle="-" if layout == "flat" else "--",
                        label=f"{layout} {block}B")
    ax.set_xscale("log", base=2); ax.set_xlabel("leaves N"); ax.set_ylabel("input MB/s")
    ax.set_title("Sequential construction throughput"); ax.legend(fontsize=7)
    fig.tight_layout(); fig.savefig(outdir / "build_seq_throughput.png", dpi=150)
    plt.close(fig)

    # Per-level busy vs wait for each levels configuration at max threads
    if med:
        for leaves, block in sorted({(k[0], k[1]) for k in med}):
            tmax = max(k[2] for k in med if k[:2] == (leaves, block))
            lv = sorted((int(k[3]), v["busy_mean"], v["wait_mean"]) for k, v in med.items()
                        if k[:3] == (leaves, block, tmax) and k[4] in ("leaf", "internal"))
            if not lv:
                continue
            lvl, busy, wait = zip(*lv)
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.bar(lvl, [b * 1e6 for b in busy], label="busy (hashing)")
            ax.bar(lvl, [w * 1e6 for w in wait], bottom=[b * 1e6 for b in busy],
                   label="barrier wait")
            ax.set_yscale("log"); ax.set_xlabel("level (0 = leaves)"); ax.set_ylabel("us")
            ax.set_title(f"Per-level time, N=2^{log2(leaves)} {block}B, {tmax} threads")
            ax.legend()
            fig.tight_layout(); fig.savefig(outdir / f"levels_N{leaves}_B{block}.png", dpi=150)
            plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_csv", type=Path)
    ap.add_argument("--levels", type=Path)
    ap.add_argument("--plots", type=Path)
    args = ap.parse_args()

    rows = load(args.build_csv)
    s = summarise_build(rows)
    cols = ["phase", "layout", "leaves", "block_bytes", "threads", "n", "median_s", "q1_s",
            "q3_s", "iqr_s", "free_median_s", "input_mb_per_s", "nodes_per_s",
            "speedup_vs_seq", "scaling_T1_over_Tp", "pointer_over_flat"]
    write_csv(args.build_csv.with_suffix(".summary.csv"), cols,
              [list(k) + [s[k][c] for c in cols[5:]] for k in sorted(s)])
    mem = memory_table(rows)
    write_csv(args.build_csv.with_suffix(".memory.csv"),
              ["layout", "leaves", "block_bytes", "model_bytes", "node_struct_bytes",
               "heap_bytes", "rss_delta_bytes", "heap_over_model", "rss_over_model",
               "build_seconds", "free_seconds"], mem)
    print(f"Wrote {args.build_csv.with_suffix('.summary.csv')} and .memory.csv")
    print_build(s, mem)

    med = {}
    if args.levels:
        med, breakdown = summarise_levels(load(args.levels))
        write_csv(args.levels.with_suffix(".summary.csv"),
                  ["leaves", "block_bytes", "threads", "level", "kind", "nodes",
                   "median_seconds", "median_busy_mean", "median_wait_mean",
                   "median_imbalance", "wait_fraction", "nodes_per_thread"],
                  level_rows(med))
        print(f"\nWrote {args.levels.with_suffix('.summary.csv')}")
        print_levels(med, breakdown)

    if args.plots:
        plots(s, med, args.plots)


if __name__ == "__main__":
    main()
