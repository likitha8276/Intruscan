"""Test 2: bootstrap confidence intervals by source host.

Cutoffs are fixed from the CALIBRATION file (smallest cutoff whose benign FPR stays within
the budget). The TEST file is resampled by whole source hosts, because flows from one
source are correlated, so resampling single flows would give intervals that are too narrow.

Usage (from the project root):
  python tools/bootstrap_ci.py \
      --calib smoke/real_diag_v3.jsonl --test smoke/test2_v3_scored.jsonl \
      --score-key s_score --label-key label --benign background \
      --src-key <source field>   # auto-detected if omitted
      --scan-types scan11 scan44 --boot 2000 --seed 7 --out smoke/bootstrap_ci.csv
"""
import argparse
import csv
import json
import sys

import numpy as np

SRC_CANDIDATES = ["src", "src_ip", "source", "sa", "src_addr", "source_ip", "srcaddr", "src_host"]


def budget_cutoff(benign_scores, fpr):
    srt = np.sort(benign_scores)
    n = len(srt)
    k = int(np.floor(fpr * n))
    if k >= n:
        return float(srt[0])
    return float(np.nextafter(srt[n - k - 1], np.inf))


def load_calib_benign(path, score_key, label_key, benign):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            r = json.loads(line)
            if str(r[label_key]) == benign:
                out.append(float(r[score_key]))
    return np.array(out)


def load_test(path, score_key, label_key, src_key):
    scores, labels, srcs = [], [], []
    keys = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            r = json.loads(line)
            if keys is None:
                keys = sorted(r.keys())
                if src_key is None:
                    for c in SRC_CANDIDATES:
                        if c in r:
                            src_key = c
                            break
                    if src_key is None:
                        sys.exit(f"No source field found. Keys: {keys}. Use --src-key.")
                for k in (score_key, label_key, src_key):
                    if k not in r:
                        sys.exit(f"Missing '{k}'. Keys: {keys}")
            scores.append(float(r[score_key]))
            labels.append(str(r[label_key]))
            srcs.append(str(r[src_key]))
    return np.array(scores), np.array(labels), np.array(srcs), src_key


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--calib", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--score-key", default="s_score")
    ap.add_argument("--label-key", default="label")
    ap.add_argument("--benign", default="background")
    ap.add_argument("--src-key", default=None)
    ap.add_argument("--scan-types", nargs="*", default=["scan11", "scan44"])
    ap.add_argument("--fpr-lo", type=float, default=0.05, help="budget for tau_l")
    ap.add_argument("--fpr-hi", type=float, default=0.01, help="budget for tau_u")
    ap.add_argument("--boot", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="bootstrap_ci.csv")
    a = ap.parse_args()

    cb = load_calib_benign(a.calib, a.score_key, a.label_key, a.benign)
    tau_l = budget_cutoff(cb, a.fpr_lo)
    tau_u = budget_cutoff(cb, a.fpr_hi)
    print(f"cutoffs from calibration only: tau_l={tau_l:.6f} (<= {a.fpr_lo:.1%}), "
          f"tau_u={tau_u:.6f} (<= {a.fpr_hi:.1%})")

    sc, lab, src, src_key = load_test(a.test, a.score_key, a.label_key, a.src_key)
    print(f"source field: {src_key}")
    uniq_src, src_idx = np.unique(src, return_inverse=True)
    S = len(uniq_src)
    n_flows = len(sc)
    print(f"test flows: {n_flows:,}; distinct sources: {S:,}")
    per_src = np.bincount(src_idx)
    print(f"largest source holds {per_src.max() / n_flows:.1%} of flows; "
          f"top 10 sources hold {np.sort(per_src)[-10:].sum() / n_flows:.1%}")

    types = sorted(set(lab) - {a.benign})
    scan_types = [t for t in a.scan_types if t in types]
    groups = {"background": lab == a.benign}
    for t in types:
        groups[t] = lab == t
    groups["all attacks"] = lab != a.benign
    if scan_types:
        groups["scans combined (" + "+".join(scan_types) + ")"] = np.isin(lab, scan_types)

    # Per-source count matrix: columns = (group, total / >=tau_l / >=tau_u)
    cols, names = [], []
    for g, mask in groups.items():
        for thr_name, thr in (("n", None), ("tl", tau_l), ("tu", tau_u)):
            m = mask if thr is None else (mask & (sc >= thr))
            cols.append(np.bincount(src_idx, weights=m.astype(float), minlength=S))
            names.append((g, thr_name))
    C = np.vstack(cols).T  # S x M
    col_of = {nm: i for i, nm in enumerate(names)}

    def stats(totals):
        out = {}
        for g in groups:
            n = totals[col_of[(g, "n")]]
            for thr_name in ("tl", "tu"):
                x = totals[col_of[(g, thr_name)]]
                out[(g, thr_name)] = x / n if n > 0 else np.nan
        return out

    point = stats(C.sum(axis=0))
    rng = np.random.default_rng(a.seed)
    boot = {k: [] for k in point}
    for _ in range(a.boot):
        w = np.bincount(rng.integers(0, S, S), minlength=S).astype(float)
        st = stats(w @ C)
        for k, v in st.items():
            boot[k].append(v)

    rows = []
    print(f"\n{'group':<34}{'cutoff':>8}{'flows':>10}{'point':>9}{'95% CI':>20}")
    for g in groups:
        n = int(C[:, col_of[(g, "n")]].sum())
        for thr_name, label in (("tl", "tau_l"), ("tu", "tau_u")):
            arr = np.array(boot[(g, thr_name)])
            lo, hi = np.nanpercentile(arr, [2.5, 97.5])
            kind = "FPR" if g == "background" else "recall"
            print(f"{g + ' ' + kind:<34}{label:>8}{n:>10,}{point[(g, thr_name)]:>9.2%}"
                  f"{'[' + format(lo, '.2%') + ', ' + format(hi, '.2%') + ']':>20}")
            rows.append(dict(group=g, metric=kind, cutoff=label, flows=n,
                             point=point[(g, thr_name)], ci_lo=lo, ci_hi=hi))

    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nwrote {a.out}  ({a.boot} bootstrap draws over {S:,} source hosts)")


if __name__ == "__main__":
    main()