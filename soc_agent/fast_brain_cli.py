"""Train and run the Layer 2 model against the Layer 1 SQLite flow archive."""

from __future__ import annotations

import argparse
import json
import random
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import TextIO

import joblib
import numpy as np

from .fast_brain import EarlyExitMVIForest, features_from_flow
from .thresholds import resolve_routing_thresholds


def train_archive(archive_path: str, model_path: str, random_state: int) -> int:
    """Fit on labeled benign records and save a production-use model."""
    features: list[np.ndarray] = []
    with sqlite3.connect(archive_path) as connection:
        rows = connection.execute(
            "SELECT raw_json FROM flow_archive "
            "WHERE lower(label) = 'benign' ORDER BY timestamp, flow_id"
        )
        for (raw_json,) in rows:
            flow = json.loads(raw_json)
            features.append(features_from_flow(flow))
    if len(features) < 2:
        raise ValueError(
            "training requires at least two flows labeled 'benign' in the archive"
        )

    forest = EarlyExitMVIForest(random_state=random_state)
    forest.fit(np.vstack(features))
    destination = Path(model_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(forest, destination)
    return len(features)


def train_jsonl(
    input_path: str,
    model_path: str,
    random_state: int,
    normal_labels: set[str],
    max_training_rows: int,
) -> int:
    """Train from JSONL with a bounded reservoir of normal-flow features."""
    if max_training_rows < 2:
        raise ValueError("max_training_rows must be at least 2")
    rng = random.Random(random_state)
    features: list[np.ndarray] = []
    seen = 0
    with open(input_path, encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                flow = json.loads(line)
                if not isinstance(flow, dict):
                    raise ValueError("each JSONL record must be an object")
                if flow.get("label") not in normal_labels:
                    continue
                vector = features_from_flow(flow)
            except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
                raise ValueError(
                    f"invalid training record at line {line_number}: {exc}"
                ) from exc

            seen += 1
            if len(features) < max_training_rows:
                features.append(vector)
            else:
                replacement = rng.randrange(seen)
                if replacement < max_training_rows:
                    features[replacement] = vector

    if len(features) < 2:
        raise ValueError(
            "training requires at least two records whose label matches "
            + ", ".join(sorted(normal_labels))
        )
    forest = EarlyExitMVIForest(random_state=random_state)
    forest.fit(np.vstack(features))
    destination = Path(model_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(forest, destination)
    return len(features)


def score_archive(
    archive_path: str,
    model_path: str,
    output: TextIO,
    thresholds_path: str | None = None,
    route_counts: Counter | None = None,
) -> int:
    """Score each archived flow and emit one JSONL result per flow.

    Routing uses the approved thresholds bound to this exact model file, or the
    built-in 0.40 / 0.85 fallback when no approved configuration exists. The chosen
    source is reported on stderr. ``route_counts``, if given, is filled per route.
    """
    forest = joblib.load(model_path)
    if not isinstance(forest, EarlyExitMVIForest):
        raise ValueError("model file does not contain an EarlyExitMVIForest")
    thresholds = resolve_routing_thresholds(thresholds_path, model_path)
    print(thresholds.describe(), file=sys.stderr)
    count = 0
    with sqlite3.connect(archive_path) as connection:
        rows = connection.execute(
            "SELECT raw_json FROM flow_archive ORDER BY timestamp, flow_id"
        )
        for (raw_json,) in rows:
            flow = json.loads(raw_json)
            score = forest.compute_s_score(features_from_flow(flow))
            result = dict(flow)
            result["s_score"] = score
            result["route"] = forest.route_flow(
                score, thresholds.lower, thresholds.upper
            )
            if route_counts is not None:
                route_counts[result["route"]] += 1
            output.write(json.dumps(result, separators=(",", ":"), allow_nan=False))
            output.write("\n")
            count += 1
    return count


def score_jsonl(
    input_path: str,
    model_path: str,
    output: TextIO,
    thresholds_path: str | None = None,
    route_counts: Counter | None = None,
) -> int:
    """Score canonical JSONL records without loading the input into memory.

    Threshold handling is identical to ``score_archive``.
    """
    forest = joblib.load(model_path)
    if not isinstance(forest, EarlyExitMVIForest):
        raise ValueError("model file does not contain an EarlyExitMVIForest")
    thresholds = resolve_routing_thresholds(thresholds_path, model_path)
    print(thresholds.describe(), file=sys.stderr)
    count = 0
    with open(input_path, encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                flow = json.loads(line)
                if not isinstance(flow, dict):
                    raise ValueError("each JSONL record must be an object")
                score = forest.compute_s_score(features_from_flow(flow))
            except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
                raise ValueError(
                    f"invalid scoring record at line {line_number}: {exc}"
                ) from exc
            result = dict(flow)
            result["s_score"] = score
            result["route"] = forest.route_flow(
                score, thresholds.lower, thresholds.upper
            )
            if route_counts is not None:
                route_counts[result["route"]] += 1
            output.write(json.dumps(result, separators=(",", ":"), allow_nan=False))
            output.write("\n")
            count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="intruscan-fast-brain")
    commands = parser.add_subparsers(dest="command", required=True)

    train_parser = commands.add_parser("train", help="fit on benign archived flows")
    train_source = train_parser.add_mutually_exclusive_group()
    train_source.add_argument("--archive", help="SQLite flow archive")
    train_source.add_argument("--input", help="canonical flow JSONL")
    train_parser.add_argument("--model", default="fast_brain.joblib")
    train_parser.add_argument("--random-state", type=int, default=7)
    train_parser.add_argument(
        "--normal-label",
        action="append",
        help="label treated as normal (repeatable; JSONL default: benign)",
    )
    train_parser.add_argument(
        "--max-training-rows",
        type=int,
        default=100_000,
        help="maximum normal flows sampled from JSONL (default: 100000)",
    )

    score_parser = commands.add_parser("score", help="score archived flows")
    score_source = score_parser.add_mutually_exclusive_group()
    score_source.add_argument("--archive", help="SQLite flow archive")
    score_source.add_argument("--input", help="canonical flow JSONL")
    score_parser.add_argument("--model", default="fast_brain.joblib")
    score_parser.add_argument("--output", help="JSONL output path (default: stdout)")
    score_parser.add_argument(
        "--thresholds",
        help=(
            "approved threshold configuration bound to --model "
            "(default: soc_agent/thresholds.json; if that file is absent the "
            "built-in 0.40/0.85 fallback is used and reported on stderr)"
        ),
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "train":
            if args.archive is None and args.input is None:
                parser.error("train requires --archive or --input")
            if args.archive:
                count = train_archive(args.archive, args.model, args.random_state)
            else:
                labels = set(args.normal_label or ["benign"])
                count = train_jsonl(
                    args.input,
                    args.model,
                    args.random_state,
                    labels,
                    args.max_training_rows,
                )
            print(f"trained on {count} normal flows; saved model to {args.model}")
            return 0

        if args.archive is None and args.input is None:
            parser.error("score requires --archive or --input")
        route_counts: Counter = Counter()
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as output:
                if args.input:
                    count = score_jsonl(
                        args.input, args.model, output, args.thresholds, route_counts
                    )
                else:
                    count = score_archive(
                        args.archive, args.model, output, args.thresholds, route_counts
                    )
            print(f"scored {count} flows; wrote results to {args.output}")
        else:
            if args.input:
                count = score_jsonl(
                    args.input, args.model, sys.stdout, args.thresholds, route_counts
                )
            else:
                count = score_archive(
                    args.archive, args.model, sys.stdout, args.thresholds, route_counts
                )
            print(f"scored {count} flows", file=sys.stderr)
        print(
            "routing summary: "
            + " ".join(
                f"{route}={route_counts.get(route, 0)}"
                for route in ("CLEAR", "SLOW_BRAIN", "FAST_TRACK")
            ),
            file=sys.stderr,
        )
        return 0
    except (OSError, sqlite3.Error, ValueError, json.JSONDecodeError) as exc:
        print(f"fast-brain error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
