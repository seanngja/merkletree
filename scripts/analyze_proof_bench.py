#!/usr/bin/env python3
"""Summarise proof benchmark CSVs: median, IQR, speedup, thread scaling.

    python3 scripts/analyze_proof_bench.py results/proof_bench_<tag>.csv [--plots DIR]

Writes <csv>.summary.csv next to the input. With --plots (and matplotlib
installed) also writes PNG figures.

Definitions (proposal Section 4):
    speedup  = T_seq / T_variant          (T_seq: verify, sched=seq, same N/leaf/batch)
    scaling  = T_1 / T_p                  (same sched; T_1 is the 1-thread run, which
                                           the library executes on its sequential path)
    throughput = batch / median seconds
"""
import argparse
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def quantiles(xs):
    xs = sorted(xs)
    if len(xs) < 2:
        return xs[0], xs[0], xs[0]
    q1, med, q3 = statistics.quantiles(xs, n=4, method="inclusive")
    return q1, med, q3


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def summarise(rows):
    groups = defaultdict(list)
    for r in rows:
        key = (r["phase"], r["layout"], int(r["leaves"]), int(r["block_bytes"]),
               int(r["batch"]), r["sched"], int(r["threads"]))
        groups[key].append(float(r["seconds"]))

    out = {}
    for key, secs in groups.items():
        q1, med, q3 = quantiles(secs)
        out[key] = {"n": len(secs), "median_s": med, "q1_s": q1, "q3_s": q3,
                    "iqr_s": q3 - q1}

    for key, s in out.items():
        phase, layout, leaves, block, batch, sched, threads = key
        s["throughput_proofs_per_s"] = batch / s["median_s"]
        s["median_ns_per_proof"] = s["median_s"] * 1e9 / batch
        s["speedup_vs_seq"] = ""
        s["scaling_T1_over_Tp"] = ""
        if phase == "verify":
            seq = out.get((phase, layout, leaves, block, batch, "seq", 1))
            if seq:
                s["speedup_vs_seq"] = seq["median_s"] / s["median_s"]
            t1 = out.get((phase, layout, leaves, block, batch, sched, 1))
            if t1 and sched != "seq":
                s["scaling_T1_over_Tp"] = t1["median_s"] / s["median_s"]
    return out


def write_summary(summary, path):
    cols = ["phase", "layout", "leaves", "block_bytes", "batch", "sched", "threads",
            "n", "median_s", "q1_s", "q3_s", "iqr_s", "median_ns_per_proof",
            "throughput_proofs_per_s", "speedup_vs_seq", "scaling_T1_over_Tp"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for key in sorted(summary):
            s = summary[key]
            w.writerow(list(key) + [s[c] for c in cols[7:]])


def print_highlights(summary):
    print("\nSingle-proof verification latency (batch=1, seq), median [IQR] us:")
    for key in sorted(summary):
        phase, layout, leaves, block, batch, sched, threads = key
        if phase == "verify" and batch == 1 and sched == "seq":
            s = summary[key]
            print(f"  N=2^{leaves.bit_length() - 1:<2} leaf={block:>4}B  "
                  f"{s['median_s'] * 1e6:9.3f}  [{s['iqr_s'] * 1e6:.3f}]")

    print("\nProof generation, median ns/proof at largest batch (seq):")
    gen = [k for k in summary if k[0] == "gen"]
    if gen:
        big = max(k[4] for k in gen)
        for key in sorted(k for k in gen if k[4] == big):
            s = summary[key]
            print(f"  {key[1]:<7} N=2^{key[2].bit_length() - 1:<2} leaf={key[3]:>4}B  "
                  f"{s['median_ns_per_proof']:9.1f}")

    print("\nBest verify speedup vs seq per (N, leaf, batch):")
    best = {}
    for key, s in summary.items():
        if key[0] == "verify" and key[5] != "seq":
            k = key[2:5]
            if k not in best or s["speedup_vs_seq"] > best[k][1]:
                best[k] = (key, s["speedup_vs_seq"])
    for k in sorted(best):
        key, sp = best[k]
        print(f"  N=2^{k[0].bit_length() - 1:<2} leaf={k[1]:>4}B batch={k[2]:>3}  "
              f"{sp:6.2f}x  ({key[5]}, {key[6]} threads)")


def plots(summary, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plots", file=sys.stderr)
        return
    outdir.mkdir(parents=True, exist_ok=True)
    verify = {k: v for k, v in summary.items() if k[0] == "verify"}
    configs = sorted({(k[2], k[3]) for k in verify})

    # Throughput vs threads, one figure per (N, leaf), one line per batch x sched
    for leaves, block in configs:
        fig, ax = plt.subplots(figsize=(6, 4))
        for sched in ("static", "dynamic"):
            for batch in sorted({k[4] for k in verify}):
                pts = sorted((k[6], v["throughput_proofs_per_s"])
                             for k, v in verify.items()
                             if k[2:6] == (leaves, block, batch, sched))
                if pts:
                    ax.plot(*zip(*pts), marker="o",
                            linestyle="-" if sched == "static" else "--",
                            label=f"{sched} b={batch}")
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("threads")
        ax.set_ylabel("proofs / s")
        ax.set_title(f"Verify throughput, N=2^{leaves.bit_length() - 1}, leaf={block}B")
        ax.legend(fontsize=6, ncol=2)
        fig.tight_layout()
        fig.savefig(outdir / f"verify_throughput_N{leaves}_B{block}.png", dpi=150)
        plt.close(fig)

    # Single-proof latency vs N, one line per leaf size
    fig, ax = plt.subplots(figsize=(6, 4))
    for block in sorted({k[3] for k in verify}):
        pts = sorted((k[2], v["median_s"] * 1e6) for k, v in verify.items()
                     if k[3] == block and k[4] == 1 and k[5] == "seq")
        if pts:
            ax.plot(*zip(*pts), marker="o", label=f"leaf={block}B")
    ax.set_xscale("log", base=2)
    ax.set_xlabel("leaves N")
    ax.set_ylabel("latency (us)")
    ax.set_title("Single-proof verification latency")
    ax.legend()
    fig.tight_layout()
    fig.savefig(outdir / "verify_single_latency.png", dpi=150)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="+", type=Path)
    ap.add_argument("--plots", type=Path)
    args = ap.parse_args()

    rows = [r for p in args.csv for r in load(p)]
    summary = summarise(rows)
    out = args.csv[0].with_suffix(".summary.csv")
    write_summary(summary, out)
    print(f"Wrote {out} ({len(summary)} configurations from {len(rows)} rows)")
    print_highlights(summary)
    if args.plots:
        plots(summary, args.plots)


if __name__ == "__main__":
    main()
