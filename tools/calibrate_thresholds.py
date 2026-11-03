#!/usr/bin/env python3
"""Suggest Fast Brain routing thresholds from labeled scored-flow JSONL."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


BENIGN_PERCENTILES = (90, 95, 99)
ANOMALOUS_PERCENTILES = (1, 5, 10)


def load_scores(path: Path, benign_label: str) -> tuple[pd.Series, pd.Series]:
    try:
        frame = pd.read_json(path, lines=True)
    except (ValueError, OSError) as exc:
        raise ValueError(f"could not read scored-flow JSONL {path}: {exc}") from exc

    required = {"label", "s_score"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(
            "input is missing required field(s): " + ", ".join(sorted(missing))
        )
    if frame.empty:
        raise ValueError("input contains no JSONL records")

    scores = pd.to_numeric(frame["s_score"], errors="coerce")
    invalid = scores.isna() | ~scores.map(math.isfinite)
    if invalid.any():
        raise ValueError(
            f"input contains {int(invalid.sum())} missing, non-numeric, or infinite s_score value(s)"
        )

    benign_mask = frame["label"].eq(benign_label)
    benign = scores[benign_mask]
    anomalous = scores[~benign_mask]
    if benign.empty:
        labels = sorted(str(label) for label in frame["label"].dropna().unique())
        raise ValueError(
            f"no rows have benign label {benign_label!r}; labels present: "
            + (", ".join(labels) if labels else "(none)")
        )
    if anomalous.empty:
        raise ValueError("no anomalous rows found; expected labels other than the benign label")
    return benign, anomalous


def print_percentiles(
    benign: pd.Series,
    anomalous: pd.Series,
    benign_label: str,
) -> tuple[float, float]:
    benign_quantiles = benign.quantile([p / 100 for p in BENIGN_PERCENTILES])
    anomalous_quantiles = anomalous.quantile(
        [p / 100 for p in ANOMALOUS_PERCENTILES]
    )

    print(f"Benign label: {benign_label!r} ({len(benign):,} flows)")
    for percentile in BENIGN_PERCENTILES:
        print(
            f"  benign {percentile:>2}th percentile: "
            f"{benign_quantiles[percentile / 100]:.6f}"
        )
    print(f"Anomalous flows: {len(anomalous):,}")
    for percentile in ANOMALOUS_PERCENTILES:
        print(
            f"  anomalous {percentile:>2}th percentile: "
            f"{anomalous_quantiles[percentile / 100]:.6f}"
        )

    lower = float(benign_quantiles[0.95])
    upper = float(anomalous_quantiles[0.05])
    print("\nSuggested thresholds (validate on held-out data):")
    print(f"  CLEAR/SLOW_BRAIN lower threshold: {lower:.6f} (benign 95th percentile)")
    print(f"  SLOW_BRAIN/FAST_TRACK upper threshold: {upper:.6f} (anomalous 5th percentile)")
    if lower >= upper:
        print(
            "  WARNING: thresholds overlap or touch; these percentiles do not "
            "define a reliable three-way separation.",
            file=sys.stderr,
        )
    else:
        print(
            "  Scores between these thresholds form the suggested SLOW_BRAIN band."
        )
    return lower, upper


def save_histogram(
    benign: pd.Series,
    anomalous: pd.Series,
    lower: float,
    upper: float,
    output_path: Path,
    benign_label: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _, axis = plt.subplots(figsize=(10, 6))
    bins = np.histogram_bin_edges(
        pd.concat((benign, anomalous), ignore_index=True), bins=50
    )
    axis.hist(
        benign,
        bins=bins,
        density=True,
        alpha=0.55,
        color="seagreen",
        label=f"Benign ({benign_label})",
    )
    axis.hist(
        anomalous,
        bins=bins,
        density=True,
        alpha=0.55,
        color="firebrick",
        label="Anomalous",
    )
    axis.axvline(
        lower,
        color="darkgreen",
        linestyle="--",
        linewidth=2,
        label=f"Benign 95th percentile ({lower:.4f})",
    )
    axis.axvline(
        upper,
        color="darkred",
        linestyle=":",
        linewidth=2,
        label=f"Anomalous 5th percentile ({upper:.4f})",
    )
    axis.set(
        title="Isolation Forest score calibration",
        xlabel="Anomaly score (s_score)",
        ylabel="Density",
    )
    axis.legend()
    axis.grid(alpha=0.2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Calibrate routing thresholds from labeled scored-flow JSONL."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("scored_flows.jsonl"),
        help="scored JSONL path (default: scored_flows.jsonl)",
    )
    parser.add_argument(
        "--benign-label",
        default="background",
        help="exact label treated as benign (default: background)",
    )
    parser.add_argument(
        "--plot",
        type=Path,
        default=Path("calibration_histogram.png"),
        help="histogram output path (default: calibration_histogram.png)",
    )
    args = parser.parse_args(argv)

    try:
        benign, anomalous = load_scores(args.input, args.benign_label)
        lower, upper = print_percentiles(benign, anomalous, args.benign_label)
        save_histogram(
            benign,
            anomalous,
            lower,
            upper,
            args.plot,
            args.benign_label,
        )
    except (OSError, ValueError) as exc:
        print(f"calibration failed: {exc}", file=sys.stderr)
        return 1

    print(f"Histogram saved to {args.plot}")
    print(
        "Note: these percentile cutoffs are distribution-based suggestions, "
        "not calibrated probabilities or guaranteed operating points."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
