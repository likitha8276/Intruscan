#!/usr/bin/env python3
"""Calibrate, evaluate and approve Fast Brain routing thresholds.

Workflow (each step is a separate, explicit action):

1. ``calibrate``  score a labelled *calibration* file with an existing trained model and
                  write a **candidate** threshold file (never active).
2. ``evaluate``   score a separate labelled *test* file with the same model and record
                  independent metrics in the candidate. Test data never changes thresholds.
3. ``approve``    explicitly promote an evaluated candidate to an approved configuration
                  bound to the model's SHA-256 fingerprint.

Running the script without a subcommand keeps the original exploratory behaviour: read
already-scored JSONL, print percentile suggestions and a histogram. That mode is not tied
to any model and can never produce a candidate or approved file.

Anomaly scores are not probabilities, and percentile or constraint-based thresholds are
starting points, not guaranteed optimal operating points.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:  # allow `python tools/calibrate_thresholds.py`
    sys.path.insert(0, str(_REPO_ROOT))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from soc_agent import thresholds as th


BENIGN_PERCENTILES = (90, 95, 99)
ANOMALOUS_PERCENTILES = (1, 5, 10)

SUBCOMMANDS = ("calibrate", "evaluate", "approve")
DEFAULT_MIN_BENIGN = 100
DEFAULT_MIN_ATTACK = 20
DEFAULT_CANDIDATE_PATH = Path("threshold_candidate.json")

PREDICTION_RULE = (
    "CLEAR = predicted benign; SLOW_BRAIN or FAST_TRACK = escalated (predicted "
    "anomalous). Escalation is not a confirmed attack."
)


# ---------------------------------------------------------------------------
# Legacy exploratory mode (pre-scored JSONL). Behaviour intentionally unchanged.
# ---------------------------------------------------------------------------


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
    *,
    lower_label: str | None = None,
    upper_label: str | None = None,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _, axis = plt.subplots(figsize=(10, 6))
    bins = np.histogram_bin_edges(
        pd.concat((pd.Series(benign), pd.Series(anomalous)), ignore_index=True),
        bins=50,
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
        label=lower_label or f"Benign 95th percentile ({lower:.4f})",
    )
    axis.axvline(
        upper,
        color="darkred",
        linestyle=":",
        linewidth=2,
        label=upper_label or f"Anomalous 5th percentile ({upper:.4f})",
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


def _legacy_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Exploratory mode: suggest thresholds from labeled scored-flow JSONL. "
            "Not tied to a model; cannot create candidate or approved thresholds. "
            "For the model-bound workflow use the subcommands: "
            + ", ".join(SUBCOMMANDS)
            + "."
        )
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
    print(
        "Exploratory mode only: scores are not tied to a model, so no candidate "
        "file was written. Use the 'calibrate' subcommand with the trained model."
    )
    return 0


# ---------------------------------------------------------------------------
# Model-bound workflow
# ---------------------------------------------------------------------------


class CalibrationError(ValueError):
    """Invalid input data or an unusable calibration request."""


class InfeasibleThresholdsError(CalibrationError):
    """No valid threshold pair satisfies the requested constraints."""


@dataclass
class FlowRecord:
    line: int
    label: str
    flow: dict[str, Any]
    flow_id: str | None


@dataclass
class ScoredFlows:
    path: Path
    sha256: str
    benign_label: str
    labels: list[str]
    flow_ids: list[str | None]
    scores: np.ndarray
    is_attack: np.ndarray

    @property
    def benign(self) -> np.ndarray:
        return self.scores[~self.is_attack]

    @property
    def attack(self) -> np.ndarray:
        return self.scores[self.is_attack]


def load_model(model_path: str | Path):
    """Load the exact trained model; never builds or fits a new one."""
    import joblib

    from soc_agent.fast_brain import EarlyExitMVIForest

    try:
        forest = joblib.load(model_path)
    except FileNotFoundError as exc:
        raise CalibrationError(f"model file not found: {model_path}") from exc
    except Exception as exc:  # joblib/pickle raise many types for a bad file
        raise CalibrationError(f"could not load model {model_path}: {exc}") from exc
    if not isinstance(forest, EarlyExitMVIForest):
        raise CalibrationError("model file does not contain an EarlyExitMVIForest")
    return forest


def read_flow_records(
    path: Path,
    benign_label: str,
    attack_labels: set[str] | None = None,
) -> list[FlowRecord]:
    """Parse and validate a labelled flow JSONL file (errors carry line numbers)."""
    records: list[FlowRecord] = []
    try:
        source = open(path, encoding="utf-8")
    except OSError as exc:
        raise CalibrationError(f"cannot read {path}: {exc}") from exc
    with source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            where = f"{path}: line {line_number}"
            try:
                flow = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CalibrationError(f"{where}: invalid JSON: {exc.msg}") from exc
            if not isinstance(flow, dict):
                raise CalibrationError(f"{where}: each record must be a JSON object")
            if "label" not in flow:
                raise CalibrationError(f"{where}: missing required field 'label'")
            label = flow["label"]
            if not isinstance(label, str) or not label.strip():
                raise CalibrationError(
                    f"{where}: label must be a non-empty string, got {label!r}"
                )
            if label != benign_label and label.casefold() == benign_label.casefold():
                raise CalibrationError(
                    f"{where}: label {label!r} differs from the benign label "
                    f"{benign_label!r} only by case; refusing to guess which it is"
                )
            if (
                attack_labels is not None
                and label != benign_label
                and label not in attack_labels
            ):
                raise CalibrationError(
                    f"{where}: label {label!r} is neither the benign label "
                    f"{benign_label!r} nor one of the --attack-label values"
                )
            raw_id = flow.get("flow_id")
            flow_id = None if raw_id is None else str(raw_id)
            records.append(FlowRecord(line_number, label, flow, flow_id))
    if not records:
        raise CalibrationError(f"{path} contains no JSONL records")
    return records


def score_flows(
    model,
    path: Path,
    benign_label: str,
    attack_labels: set[str] | None = None,
) -> ScoredFlows:
    """Score every flow in ``path`` with the loaded model (no fitting)."""
    from soc_agent.fast_brain import features_from_flow

    records = read_flow_records(path, benign_label, attack_labels)
    scores = np.empty(len(records), dtype=np.float64)
    for index, record in enumerate(records):
        where = f"{path}: line {record.line}"
        try:
            score = model.compute_s_score(features_from_flow(record.flow))
        except (KeyError, TypeError, ValueError) as exc:
            raise CalibrationError(f"{where}: cannot score flow: {exc}") from exc
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise CalibrationError(
                f"{where}: model produced an invalid s_score {score!r}"
            )
        scores[index] = score
    labels = [record.label for record in records]
    return ScoredFlows(
        path=path,
        sha256=th.file_sha256(path),
        benign_label=benign_label,
        labels=labels,
        flow_ids=[record.flow_id for record in records],
        scores=scores,
        is_attack=np.array([label != benign_label for label in labels], dtype=bool),
    )


def require_sample_counts(
    data: ScoredFlows, min_benign: int, min_attack: int, what: str
) -> None:
    n_benign = int((~data.is_attack).sum())
    n_attack = int(data.is_attack.sum())
    if n_benign == 0:
        present = ", ".join(sorted(set(data.labels))) or "(none)"
        raise CalibrationError(
            f"{what}: no rows have benign label {data.benign_label!r}; "
            f"labels present: {present}"
        )
    if n_attack == 0:
        raise CalibrationError(
            f"{what}: no attack rows found; expected labels other than "
            f"{data.benign_label!r}"
        )
    if n_benign < min_benign:
        raise CalibrationError(
            f"{what}: only {n_benign} benign samples; at least {min_benign} "
            "required (see --min-benign)"
        )
    if n_attack < min_attack:
        raise CalibrationError(
            f"{what}: only {n_attack} attack samples; at least {min_attack} "
            "required (see --min-attack)"
        )


# --- statistics --------------------------------------------------------------


def _ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def percentile_table(values: np.ndarray, points: tuple[int, ...]) -> dict[str, float]:
    return {f"p{p}": float(np.quantile(values, p / 100)) for p in points}


def overlap_report(benign: np.ndarray, attack: np.ndarray) -> dict[str, Any]:
    benign_p95 = float(np.quantile(benign, 0.95))
    attack_p5 = float(np.quantile(attack, 0.05))
    benign_max = float(benign.max())
    attack_min = float(attack.min())
    return {
        "benign_max": benign_max,
        "attack_min": attack_min,
        "ranges_overlap": attack_min <= benign_max,
        "benign_p95": benign_p95,
        "attack_p5": attack_p5,
        "percentiles_overlap": benign_p95 >= attack_p5,
        "attack_fraction_at_or_below_benign_p95": float(np.mean(attack <= benign_p95)),
        "requires_acknowledgement": attack_min <= benign_max,
    }


def route_metrics(
    scores: np.ndarray, is_attack: np.ndarray, lower: float, upper: float
) -> dict[str, Any]:
    """Binary escalation metrics and three-way routing, reported separately.

    Routing rule: score < lower -> CLEAR; lower <= score <= upper -> SLOW_BRAIN;
    score > upper -> FAST_TRACK. Escalation (SLOW_BRAIN or FAST_TRACK) is controlled
    by the lower threshold; FAST_TRACK is controlled by the upper threshold.
    """
    scores = np.asarray(scores, dtype=np.float64)
    is_attack = np.asarray(is_attack, dtype=bool)
    benign = ~is_attack
    clear = scores < lower
    fast = scores > upper
    slow = ~clear & ~fast
    escalated = ~clear

    tp = int((is_attack & escalated).sum())
    fp = int((benign & escalated).sum())
    tn = int((benign & clear).sum())
    fn = int((is_attack & clear).sum())
    precision = _ratio(tp, tp + fp)
    escalation_recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    false_positive_rate = _ratio(fp, fp + tn)
    f1 = None
    if precision is not None and escalation_recall is not None:
        total = precision + escalation_recall
        f1 = None if total == 0 else 2 * precision * escalation_recall / total

    n = int(scores.size)
    n_attack = int(is_attack.sum())
    n_benign = int(benign.sum())
    ft_attack = int((is_attack & fast).sum())
    ft_benign = int((benign & fast).sum())

    def distribution(mask: np.ndarray) -> dict[str, Any]:
        total = int(mask.sum())
        counts = {
            "CLEAR": int((mask & clear).sum()),
            "SLOW_BRAIN": int((mask & slow).sum()),
            "FAST_TRACK": int((mask & fast).sum()),
        }
        return {
            "total": total,
            "counts": counts,
            "percent": {
                route: (None if total == 0 else 100.0 * count / total)
                for route, count in counts.items()
            },
        }

    return {
        "lower_threshold": float(lower),
        "upper_threshold": float(upper),
        "n": n,
        "n_benign": n_benign,
        "n_attack": n_attack,
        "prediction_rule": PREDICTION_RULE,
        "escalation": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": precision,
            "escalation_recall": escalation_recall,
            "specificity": specificity,
            "f1": f1,
            "false_positive_rate": false_positive_rate,
        },
        "fast_track": {
            "attack_flows_fast_tracked": ft_attack,
            "benign_flows_fast_tracked": ft_benign,
            "fast_track_recall": _ratio(ft_attack, n_attack),
            "fast_track_precision": _ratio(ft_attack, ft_attack + ft_benign),
            "benign_fast_track_rate": _ratio(ft_benign, n_benign),
        },
        "routing_distribution": {
            "all": distribution(np.ones(n, dtype=bool)),
            "benign": distribution(benign),
            "attack": distribution(is_attack),
        },
    }


def _fmt(value: float | None, percent: bool = False) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}%" if percent else f"{value:.4f}"


def print_metrics(title: str, metrics: dict[str, Any]) -> None:
    esc = metrics["escalation"]
    ft = metrics["fast_track"]
    dist = metrics["routing_distribution"]
    print(f"\n{title}")
    print(
        f"  samples: {metrics['n']} ({metrics['n_benign']} benign, "
        f"{metrics['n_attack']} attack); thresholds lower={metrics['lower_threshold']:.6f} "
        f"upper={metrics['upper_threshold']:.6f}"
    )
    print(f"  binary rule: {metrics['prediction_rule']}")
    print(
        f"  escalation: TP={esc['tp']} FP={esc['fp']} TN={esc['tn']} FN={esc['fn']}"
    )
    print(
        f"    precision={_fmt(esc['precision'])} "
        f"escalation_recall={_fmt(esc['escalation_recall'])} "
        f"specificity={_fmt(esc['specificity'])} f1={_fmt(esc['f1'])} "
        f"false_positive_rate={_fmt(esc['false_positive_rate'])}"
    )
    print(
        "  FAST_TRACK (separate from escalation; controlled by the upper threshold): "
        f"fast_track_recall={_fmt(ft['fast_track_recall'])} "
        f"fast_track_precision={_fmt(ft['fast_track_precision'])} "
        f"benign_fast_track_rate={_fmt(ft['benign_fast_track_rate'])}"
    )
    for name in ("all", "benign", "attack"):
        part = dist[name]
        pct = part["percent"]
        print(
            f"  routing ({name}, n={part['total']}): "
            f"CLEAR={_fmt(pct['CLEAR'], True)} "
            f"SLOW_BRAIN={_fmt(pct['SLOW_BRAIN'], True)} "
            f"FAST_TRACK={_fmt(pct['FAST_TRACK'], True)}"
        )


# --- threshold selection (calibration data only) -----------------------------


def lower_for_benign_escalation_rate(benign: np.ndarray, rate: float) -> float:
    """Smallest lower threshold whose benign escalation rate (score >= lower) <= rate.

    The smallest qualifying value maximises escalation recall on the calibration data.
    """
    values = np.unique(benign)
    for value in values:
        if float(np.mean(benign >= value)) <= rate:
            return float(value)
    above = float(np.nextafter(values[-1], 2.0))
    if above <= 1.0 and float(np.mean(benign >= above)) <= rate:
        return above
    raise InfeasibleThresholdsError(
        f"no lower threshold in [0, 1] keeps the benign escalation rate <= {rate}"
    )


def upper_for_fast_track_recall(attack: np.ndarray, recall: float) -> float:
    """Largest upper threshold whose FAST_TRACK recall (score > upper) >= recall.

    The largest qualifying value sends the fewest benign flows to FAST_TRACK.
    """
    chosen: float | None = None
    for value in np.unique(attack):
        if float(np.mean(attack > value)) >= recall:
            chosen = float(value)
    if chosen is not None:
        return chosen
    below = float(np.nextafter(attack.min(), -1.0))
    if below >= 0.0 and float(np.mean(attack > below)) >= recall:
        return below
    raise InfeasibleThresholdsError(
        f"no upper threshold in [0, 1] gives FAST_TRACK recall >= {recall}"
    )


def select_thresholds(
    benign: np.ndarray,
    attack: np.ndarray,
    *,
    max_benign_escalation_rate: float | None = None,
    min_escalation_recall: float | None = None,
    min_fast_track_recall: float | None = None,
    max_benign_fast_track_rate: float | None = None,
    explicit: tuple[float, float] | None = None,
) -> tuple[float, float, dict[str, Any]]:
    """Choose thresholds from calibration scores only.

    The lower threshold governs *escalation* (CLEAR vs SLOW_BRAIN/FAST_TRACK); the upper
    threshold governs *FAST_TRACK*. Escalation recall and FAST_TRACK recall are different
    quantities and are constrained separately.
    """
    if explicit is not None:
        lower, upper = explicit
        selection = {
            "lower": {"method": "explicit_operating_point", "selected_by": "user"},
            "upper": {"method": "explicit_operating_point", "selected_by": "user"},
            "objective": (
                "Operating point supplied explicitly by the user; it must have been "
                "chosen without looking at test data."
            ),
        }
        return lower, upper, selection

    if max_benign_escalation_rate is None:
        lower = float(np.quantile(benign, 0.95))
        lower_sel: dict[str, Any] = {
            "method": "benign_percentile",
            "percentile": 95,
            "note": "baseline: roughly 5% of calibration benign flows escalate",
        }
    else:
        lower = lower_for_benign_escalation_rate(benign, max_benign_escalation_rate)
        lower_sel = {
            "method": "max_benign_escalation_rate",
            "value": max_benign_escalation_rate,
            "note": "smallest lower threshold meeting the benign escalation cap",
        }
    escalation_recall = float(np.mean(attack >= lower))
    lower_sel["calibration_escalation_recall"] = escalation_recall
    if min_escalation_recall is not None:
        lower_sel["min_escalation_recall_required"] = min_escalation_recall
        if escalation_recall < min_escalation_recall:
            raise InfeasibleThresholdsError(
                f"lower threshold {lower:.6f} gives calibration escalation recall "
                f"{escalation_recall:.4f} < required {min_escalation_recall}; "
                "relax the benign escalation cap or the recall requirement"
            )

    if min_fast_track_recall is None:
        upper = float(np.quantile(attack, 0.05))
        upper_sel: dict[str, Any] = {
            "method": "attack_percentile",
            "percentile": 5,
            "note": "baseline: roughly 95% of calibration attack flows exceed it",
        }
    else:
        upper = upper_for_fast_track_recall(attack, min_fast_track_recall)
        upper_sel = {
            "method": "min_fast_track_recall",
            "value": min_fast_track_recall,
            "note": "largest upper threshold meeting the FAST_TRACK recall floor",
        }
    benign_ft_rate = float(np.mean(benign > upper))
    upper_sel["calibration_fast_track_recall"] = float(np.mean(attack > upper))
    upper_sel["calibration_benign_fast_track_rate"] = benign_ft_rate
    if max_benign_fast_track_rate is not None:
        upper_sel["max_benign_fast_track_rate_allowed"] = max_benign_fast_track_rate
        if benign_ft_rate > max_benign_fast_track_rate:
            raise InfeasibleThresholdsError(
                f"upper threshold {upper:.6f} sends {benign_ft_rate:.4f} of calibration "
                f"benign flows to FAST_TRACK > allowed {max_benign_fast_track_rate}; "
                "relax the FAST_TRACK recall floor or the benign FAST_TRACK cap"
            )

    selection = {
        "lower": lower_sel,
        "upper": upper_sel,
        "objective": (
            "Lower threshold: bound the benign flows that escalate (it controls "
            "escalation recall). Upper threshold: bound FAST_TRACK recall / benign "
            "FAST_TRACK rate. Chosen on calibration data only; not probabilistic "
            "and not guaranteed optimal."
        ),
    }
    return lower, upper, selection


# --- subcommands -------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _check_fraction(parser, name: str, value: float | None, *, closed_low: bool, closed_high: bool):
    if value is None:
        return
    low_ok = value >= 0.0 if closed_low else value > 0.0
    high_ok = value <= 1.0 if closed_high else value < 1.0
    if not (math.isfinite(value) and low_ok and high_ok):
        parser.error(f"{name} must be between 0 and 1 (got {value})")


def _calibrate(args, parser) -> int:
    for name in ("min_benign", "min_attack"):
        if getattr(args, name) < 1:
            parser.error(f"--{name.replace('_', '-')} must be at least 1")
    _check_fraction(parser, "--max-benign-escalation-rate", args.max_benign_escalation_rate, closed_low=True, closed_high=False)
    _check_fraction(parser, "--min-escalation-recall", args.min_escalation_recall, closed_low=False, closed_high=True)
    _check_fraction(parser, "--min-fast-track-recall", args.min_fast_track_recall, closed_low=False, closed_high=True)
    _check_fraction(parser, "--max-benign-fast-track-rate", args.max_benign_fast_track_rate, closed_low=True, closed_high=False)

    constraint_flags = (
        args.max_benign_escalation_rate,
        args.min_escalation_recall,
        args.min_fast_track_recall,
        args.max_benign_fast_track_rate,
    )
    if (args.lower is None) != (args.upper is None):
        parser.error("--lower and --upper must be given together")
    explicit = None
    if args.lower is not None:
        if any(flag is not None for flag in constraint_flags):
            parser.error("--lower/--upper cannot be combined with constraint options")
        explicit = (args.lower, args.upper)

    candidate_path = args.candidate_output
    if candidate_path.resolve() == th.DEFAULT_APPROVED_PATH.resolve():
        raise CalibrationError(
            "candidate output must not be the approved thresholds path "
            f"({th.DEFAULT_APPROVED_PATH}); candidates are never active"
        )
    if candidate_path.exists() and not args.overwrite_candidate:
        raise CalibrationError(
            f"{candidate_path} already exists; choose another --candidate-output "
            "or pass --overwrite-candidate"
        )

    model = load_model(args.model)
    model_sha = th.model_fingerprint(args.model)
    attack_labels = set(args.attack_label) if args.attack_label else None
    data = score_flows(model, args.input, args.benign_label, attack_labels)
    require_sample_counts(data, args.min_benign, args.min_attack, "calibration data")

    benign, attack = data.benign, data.attack
    overlap = overlap_report(benign, attack)
    print(f"Model: {args.model} (sha256 {model_sha[:16]}...)")
    print(
        f"Calibration data: {args.input} (sha256 {data.sha256[:16]}...): "
        f"{len(benign):,} benign ({args.benign_label!r}), {len(attack):,} attack"
    )
    benign_pct = percentile_table(benign, BENIGN_PERCENTILES)
    attack_pct = percentile_table(attack, ANOMALOUS_PERCENTILES)
    for key, value in benign_pct.items():
        print(f"  benign {key}: {value:.6f}")
    for key, value in attack_pct.items():
        print(f"  attack {key}: {value:.6f}")
    if overlap["ranges_overlap"]:
        print(
            "WARNING: benign and attack score ranges overlap "
            f"(attack min {overlap['attack_min']:.6f} <= benign max "
            f"{overlap['benign_max']:.6f}); "
            f"{overlap['attack_fraction_at_or_below_benign_p95']:.1%} of attack flows "
            "score at or below the benign 95th percentile.",
            file=sys.stderr,
        )

    try:
        lower, upper, selection = select_thresholds(
            benign,
            attack,
            max_benign_escalation_rate=args.max_benign_escalation_rate,
            min_escalation_recall=args.min_escalation_recall,
            min_fast_track_recall=args.min_fast_track_recall,
            max_benign_fast_track_rate=args.max_benign_fast_track_rate,
            explicit=explicit,
        )
        lower, upper = th.validate_thresholds(lower, upper)
    except (th.ThresholdConfigError, InfeasibleThresholdsError) as exc:
        print(f"\nNo reliable threshold pair could be selected: {exc}", file=sys.stderr)
        print(
            "No candidate file was written. The score distributions do not separate "
            "cleanly with these settings. Options: choose explicit --lower/--upper "
            "from calibration data (not test data), set a constraint option, or "
            "improve the model/features and recalibrate.",
            file=sys.stderr,
        )
        return 2

    metrics = route_metrics(data.scores, data.is_attack, lower, upper)
    print(f"\nCandidate thresholds: lower={lower:.6f} upper={upper:.6f}")
    print(f"  lower ({selection['lower']['method']}): escalation boundary")
    print(f"  upper ({selection['upper']['method']}): FAST_TRACK boundary")
    print_metrics("Calibration-set metrics (IN-SAMPLE, optimistic; not a performance claim)", metrics)

    candidate: dict[str, Any] = {
        "schema_version": th.SCHEMA_VERSION,
        "status": th.STATUS_CANDIDATE,
        "lower_threshold": lower,
        "upper_threshold": upper,
        "model_sha256": model_sha,
        "model_file": Path(args.model).name,
        "created_at": _now(),
        "benign_label": args.benign_label,
        "calibration": {
            "input_file": Path(args.input).name,
            "input_sha256": data.sha256,
            "n_records": int(len(data.scores)),
            "n_benign": int(len(benign)),
            "n_attack": int(len(attack)),
            "attack_label_counts": {
                label: data.labels.count(label)
                for label in sorted({l for l in data.labels if l != args.benign_label})
            },
            "min_benign_required": args.min_benign,
            "min_attack_required": args.min_attack,
            "benign_percentiles": benign_pct,
            "attack_percentiles": attack_pct,
        },
        "selection": selection,
        "overlap": overlap,
        "calibration_metrics": metrics,
        "evaluation": None,
        "evaluation_runs": 0,
        "notes": (
            "CANDIDATE: not active and not approved. Anomaly scores are not "
            "probabilities. Calibration metrics are in-sample."
        ),
    }
    th.atomic_write_json(candidate_path, candidate, overwrite=args.overwrite_candidate)

    if args.plot is not None:
        save_histogram(
            benign,
            attack,
            lower,
            upper,
            args.plot,
            args.benign_label,
            lower_label=f"Lower threshold ({lower:.4f})",
            upper_label=f"Upper threshold ({upper:.4f})",
        )
        print(f"\nHistogram saved to {args.plot}")
    print(f"Candidate written to {candidate_path} (status: candidate; NOT active).")
    print("Next: run 'evaluate' on a separate test file, then 'approve'.")
    return 0


def _flow_id_check(calibration: list[FlowRecord], test: list[FlowRecord]) -> dict[str, Any]:
    cal_ids = {record.flow_id for record in calibration if record.flow_id is not None}
    test_ids = {record.flow_id for record in test if record.flow_id is not None}
    result = {
        "calibration_records_with_flow_id": sum(r.flow_id is not None for r in calibration),
        "test_records_with_flow_id": sum(r.flow_id is not None for r in test),
        "calibration_records": len(calibration),
        "test_records": len(test),
    }
    shared = sorted(cal_ids & test_ids)
    if shared:
        sample = ", ".join(shared[:10]) + (" ..." if len(shared) > 10 else "")
        raise CalibrationError(
            f"data leakage: {len(shared)} flow_id value(s) appear in both the "
            f"calibration and test files (e.g. {sample}); use disjoint splits"
        )
    result["overlapping_flow_ids"] = 0
    if not cal_ids or not test_ids:
        result["status"] = "unavailable"
        result["note"] = "flow_id missing on one side; overlap could not be checked"
    elif len(cal_ids) < len(calibration) or len(test_ids) < len(test):
        result["status"] = "partial"
        result["note"] = "some records lack flow_id; overlap checked only where available"
    else:
        result["status"] = "passed"
    return result


def _evaluate(args, parser) -> int:
    candidate = th.read_json_object(args.candidate)
    config = th.validate_config(
        candidate,
        expect_status=th.STATUS_CANDIDATE,
        model_sha256=th.model_fingerprint(args.model),
        label=f"candidate {args.candidate}",
    )
    benign_label = candidate.get("benign_label")
    if not isinstance(benign_label, str) or not benign_label:
        raise CalibrationError("candidate has no benign_label")
    recorded = candidate.get("calibration", {}).get("input_sha256")
    cal_sha = th.file_sha256(args.calibration_input)
    if recorded != cal_sha:
        raise CalibrationError(
            "--calibration-input is not the file this candidate was calibrated on "
            "(SHA-256 mismatch)"
        )
    test_sha = th.file_sha256(args.input)
    if test_sha == cal_sha:
        raise CalibrationError(
            "test file is identical to the calibration file; use independent test data"
        )

    attack_labels = set(args.attack_label) if args.attack_label else None
    cal_records = read_flow_records(args.calibration_input, benign_label, attack_labels)
    test_records = read_flow_records(args.input, benign_label, attack_labels)
    id_check = _flow_id_check(cal_records, test_records)

    model = load_model(args.model)
    test = score_flows(model, args.input, benign_label, attack_labels)
    require_sample_counts(test, args.min_benign, args.min_attack, "test data")

    metrics = route_metrics(test.scores, test.is_attack, config.lower, config.upper)
    print(f"Evaluating candidate thresholds lower={config.lower:.6f} upper={config.upper:.6f}")
    print(f"flow_id overlap check: {id_check['status']}")
    print_metrics("Independent test-set metrics", metrics)

    candidate["evaluation"] = {
        "evaluated_at": _now(),
        "thresholds_evaluated": {"lower": config.lower, "upper": config.upper},
        "test_input_file": Path(args.input).name,
        "test_input_sha256": test_sha,
        "n_records": int(len(test.scores)),
        "n_benign": metrics["n_benign"],
        "n_attack": metrics["n_attack"],
        "flow_id_check": id_check,
        "metrics": metrics,
        "note": (
            "Test data was used only to measure these thresholds; it did not select "
            "or adjust them."
        ),
    }
    candidate["evaluation_runs"] = int(candidate.get("evaluation_runs") or 0) + 1
    th.atomic_write_json(args.candidate, candidate, overwrite=True)
    print(f"\nEvaluation recorded in {args.candidate} (run #{candidate['evaluation_runs']}).")
    print(
        "Thresholds were not modified. Do not tune thresholds against this test set; "
        "if they are unsatisfactory, recalibrate on calibration data and use a fresh test set."
    )
    return 0


def _approve(args, parser) -> int:
    if not args.approved_by.strip():
        parser.error("--approved-by must not be empty")
    candidate = th.read_json_object(args.candidate)
    config = th.validate_config(
        candidate,
        expect_status=th.STATUS_CANDIDATE,
        model_sha256=th.model_fingerprint(args.model),
        label=f"candidate {args.candidate}",
    )
    evaluation = candidate.get("evaluation")
    if not isinstance(evaluation, dict) or not isinstance(evaluation.get("metrics"), dict):
        raise CalibrationError(
            "candidate has no independent test evaluation; run 'evaluate' first"
        )
    evaluated = evaluation.get("thresholds_evaluated") or {}
    if (evaluated.get("lower"), evaluated.get("upper")) != (config.lower, config.upper):
        raise CalibrationError(
            "the recorded evaluation was made for different thresholds than this "
            "candidate now holds; re-run 'evaluate'"
        )
    overlap = candidate.get("overlap") or {}
    if overlap.get("requires_acknowledgement") and not args.acknowledge_overlap:
        raise CalibrationError(
            "calibration benign and attack score ranges overlap; review the "
            "evaluation and re-run with --acknowledge-overlap to approve explicitly"
        )

    approved = dict(candidate)
    approved["status"] = th.STATUS_APPROVED
    approved["approved_at"] = _now()
    approved["approved_by"] = args.approved_by.strip()
    approved["overlap_acknowledged"] = bool(args.acknowledge_overlap)
    approved["notes"] = (
        "APPROVED for the model whose SHA-256 is recorded in model_sha256. Invalid for "
        "any other model file. Retraining requires recalibration and re-approval."
    )
    th.validate_config(approved, expect_status=th.STATUS_APPROVED, model_sha256=config.model_sha256)
    th.atomic_write_json(args.output, approved, overwrite=args.replace)
    print(
        f"Approved thresholds lower={config.lower:.6f} upper={config.upper:.6f} "
        f"for model {config.model_sha256[:16]}... written to {args.output}"
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="calibrate_thresholds",
        description="Model-bound Fast Brain threshold calibration workflow.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    cal = commands.add_parser("calibrate", help="score calibration data and write a CANDIDATE")
    cal.add_argument("--model", required=True, type=Path, help="trained .joblib model")
    cal.add_argument("--input", required=True, type=Path, help="labelled calibration flow JSONL")
    cal.add_argument("--benign-label", required=True, help="exact label treated as benign (required)")
    cal.add_argument("--attack-label", action="append", help="allowed attack label (repeatable); other labels are rejected")
    cal.add_argument("--min-benign", type=int, default=DEFAULT_MIN_BENIGN)
    cal.add_argument("--min-attack", type=int, default=DEFAULT_MIN_ATTACK)
    cal.add_argument("--max-benign-escalation-rate", type=float, help="cap on calibration benign flows escalated (lower threshold)")
    cal.add_argument("--min-escalation-recall", type=float, help="required calibration escalation recall (SLOW_BRAIN or FAST_TRACK)")
    cal.add_argument("--min-fast-track-recall", type=float, help="floor on calibration FAST_TRACK recall (upper threshold)")
    cal.add_argument("--max-benign-fast-track-rate", type=float, help="cap on calibration benign flows sent to FAST_TRACK")
    cal.add_argument("--lower", type=float, help="explicit lower threshold (with --upper)")
    cal.add_argument("--upper", type=float, help="explicit upper threshold (with --lower)")
    cal.add_argument("--candidate-output", type=Path, default=DEFAULT_CANDIDATE_PATH)
    cal.add_argument("--overwrite-candidate", action="store_true")
    cal.add_argument("--plot", type=Path, default=Path("calibration_histogram.png"))

    ev = commands.add_parser("evaluate", help="evaluate a candidate on independent test data")
    ev.add_argument("--candidate", required=True, type=Path)
    ev.add_argument("--model", required=True, type=Path)
    ev.add_argument("--calibration-input", required=True, type=Path, help="the calibration file used for this candidate (for split checks)")
    ev.add_argument("--input", required=True, type=Path, help="labelled TEST flow JSONL")
    ev.add_argument("--attack-label", action="append")
    ev.add_argument("--min-benign", type=int, default=DEFAULT_MIN_BENIGN)
    ev.add_argument("--min-attack", type=int, default=DEFAULT_MIN_ATTACK)

    ap = commands.add_parser("approve", help="explicitly approve an evaluated candidate")
    ap.add_argument("--candidate", required=True, type=Path)
    ap.add_argument("--model", required=True, type=Path)
    ap.add_argument("--output", type=Path, default=th.DEFAULT_APPROVED_PATH)
    ap.add_argument("--approved-by", required=True)
    ap.add_argument("--replace", action="store_true", help="replace an existing approved configuration")
    ap.add_argument("--acknowledge-overlap", action="store_true", help="approve despite overlapping calibration score ranges")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in SUBCOMMANDS:
        return _legacy_main(arguments)

    parser = _build_parser()
    args = parser.parse_args(arguments)
    handlers = {"calibrate": _calibrate, "evaluate": _evaluate, "approve": _approve}
    try:
        return handlers[args.command](args, parser)
    except FileNotFoundError as exc:
        print(f"{args.command} failed: file not found: {exc.filename or exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:  # CalibrationError / ThresholdConfigError are ValueErrors
        print(f"{args.command} failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
