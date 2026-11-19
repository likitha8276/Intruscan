"""Test 1: recall at fixed false-positive rates, thresholds set on the calibration day only.

Usage (from the project root):
  python tools/eval_operating_points.py \
      --calib smoke/ugr16_28jul_scored.jsonl \
      --test  smoke/ugr16_29jul_scored.jsonl \
      --score-key s_score --label-key label --benign background \
      --exclude blacklist --out smoke/operating_points.csv

Rules followed:
  * Cutoffs come from the CALIBRATION file's benign scores only: the smallest cutoff whose
    calibration FPR does not exceed the target (matters because scores contain ties).
  * The TEST file is only scored with those cutoffs (never used to pick them).
  * The recall-vs-FPR curve on the test day is descriptive, not used for selection.
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict

import numpy as np

FPR_TARGETS = [0.001, 0.01, 0.05]
TAU_L, TAU_U = 0.596033, 0.635351  # current paper cutoffs (Table 1)


def load(path, score_key, label_key):
    scores, labels = [], []
    seen_keys = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if seen_keys is None:
                seen_keys = sorted(rec.keys())
            if score_key not in rec or label_key not in rec:
                sys.exit(
                    f"{path}: missing '{score_key}' or '{label_key}'. "
                    f"Keys in first record: {seen_keys}. Use --score-key / --label-key."
                )
            scores.append(float(rec[score_key]))
            labels.append(str(rec[label_key]))
    return np.array(scores), np.array(labels)


def split(scores, labels, benign, exclude):
    keep = ~np.isin(labels, list(exclude))
    scores, labels = scores[keep], labels[keep]
    is_benign = labels == benign
    return scores[is_benign], scores[~is_benign], labels[~is_benign]


def budget_cutoff(benign_scores, fpr):
    """Smallest cutoff whose benign FPR is <= fpr (never over budget, even with ties)."""
    srt = np.sort(benign_scores)
    n = len(srt)
    k = int(np.floor(fpr * n))  # flows allowed at or above the cutoff
    if k >= n:
        return float(srt[0])
    t0 = srt[n - k - 1]  # the (k+1)-th largest score: must stay below the cutoff
    return float(np.nextafter(t0, np.inf))


def recall_at(threshold, atk_scores):
    return float((atk_scores >= threshold).mean()) if len(atk_scores) else float("nan")


def fpr_at(threshold, ben_scores):
    return float((ben_scores >= threshold).mean()) if len(ben_scores) else float("nan")


def report(name, calib, test, benign, exclude, rows):
    cb, ca, _ = split(*calib, benign, exclude)
    tb, ta, tl = split(*test, benign, exclude)
    print(f"\n=== {name} (excluded: {sorted(exclude) or 'none'}) ===")
    print(f"calib: {len(cb):,} benign, {len(ca):,} attack | "
          f"test: {len(tb):,} benign, {len(ta):,} attack")
    print(f"{'target FPR':>10} {'cutoff':>9} {'calib FPR':>10} {'calib recall':>13} "
          f"{'test recall':>12} {'test FPR':>9}")
    for f in FPR_TARGETS:
        thr = budget_cutoff(cb, f)  # from calibration benign only, never over budget
        row = dict(setting=name, target_fpr=f, cutoff=thr,
                   calib_fpr=fpr_at(thr, cb),
                   calib_recall=recall_at(thr, ca), test_recall=recall_at(thr, ta),
                   test_fpr=fpr_at(thr, tb))
        rows.append(row)
        print(f"{f:>10.3%} {thr:>9.6f} {row['calib_fpr']:>9.2%} {row['calib_recall']:>12.2%} "
              f"{row['test_recall']:>11.2%} {row['test_fpr']:>8.2%}")
    thr = TAU_L
    print(f"{'paper tau_l':>10} {thr:>9.6f} {fpr_at(thr, cb):>9.2%} {recall_at(thr, ca):>12.2%} "
          f"{recall_at(thr, ta):>11.2%} {fpr_at(thr, tb):>8.2%}")

    # recall by attack type at each target cutoff, test day
    print("recall by attack type on test (rows: type; cols: target FPR)")
    types = sorted(set(tl))
    header = "".join(f"{f:>10.3%}" for f in FPR_TARGETS)
    print(f"{'type':<14}{'flows':>9}{header}")
    for t in types:
        m = tl == t
        cells = ""
        for f in FPR_TARGETS:
            thr = budget_cutoff(cb, f)
            cells += f"{recall_at(thr, ta[m]):>10.1%}"
        print(f"{t:<14}{int(m.sum()):>9,}{cells}")
    return cb, ca, tb, ta


def write_curve(path, tb, ta):
    # Descriptive curve on the test day (not used to choose cutoffs).
    grid = np.unique(np.quantile(tb, np.linspace(0, 1, 501)))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["cutoff", "fpr", "recall"])
        for thr in grid:
            w.writerow([f"{thr:.6f}", f"{fpr_at(thr, tb):.6f}", f"{recall_at(thr, ta):.6f}"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--calib", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--score-key", default="s_score")
    ap.add_argument("--label-key", default="label")
    ap.add_argument("--benign", default="background")
    ap.add_argument("--exclude", nargs="*", default=["blacklist"],
                    help="attack labels to leave out of the 'without' run")
    ap.add_argument("--out", default="operating_points.csv")
    a = ap.parse_args()

    calib = load(a.calib, a.score_key, a.label_key)
    test = load(a.test, a.score_key, a.label_key)
    print("label counts calib:", {str(k): v for k, v in Counter(calib[1]).items()})
    print("label counts test :", {str(k): v for k, v in Counter(test[1]).items()})

    rows = []
    report("with all attack types", calib, test, a.benign, set(), rows)
    cb, ca, tb, ta = report("without " + "/".join(a.exclude), calib, test,
                            a.benign, set(a.exclude), rows)

    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    curve = a.out.replace(".csv", "_curve.csv")
    write_curve(curve, *split(*test, a.benign, set(a.exclude))[:2])
    print(f"\nwrote {a.out} and {curve}")


if __name__ == "__main__":
    main()