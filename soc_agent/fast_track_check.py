"""Rule-based evidence check for FAST_TRACK incidents. No LLM is involved.

FAST_TRACK flows are recorded as HIGH-priority incidents without an LLM call, by design.
The Layer 4 verifier and risk gate cannot run on them: both examine claims and proposed
actions that the LLM produces, and a FAST_TRACK incident has neither.

This module adds a separate, explicitly rule-based check. For each FAST_TRACK incident it
compares the flow against the other flows from the same source in the scored file
(the evidence) and applies a few written-down rules:

  verdicts    what the evidence says (score margin, corroboration, source context)
              The score margin is reported but is NOT a gate flag: the upper threshold is the
              benign 99th percentile, so FAST_TRACK scores sit just above it by construction.
  gate_flags  reasons the HIGH priority deserves a second look

It never changes the incident's priority or route: FAST_TRACK stays HIGH. The result is
stored under ``evidence["rule_check"]`` of the incident, so no schema change is needed.

The rule parameters below are heuristics. They are NOT calibrated or validated, and this
check is NOT the LLM verifier or risk gate. The ground-truth label is never read.

    python -m soc_agent.fast_track_check --scored scored_flows.jsonl --incident-db incidents.db
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter, defaultdict
from contextlib import closing
from pathlib import Path
from typing import Any, Mapping

CHECK_TYPE = "rule_based_no_llm"
RULES_VERSION = 2

# Heuristic parameters (uncalibrated; see module docstring).
MIN_CORROBORATION = 3           # FAST_TRACK flows from one source that count as corroborated
MOSTLY_CLEAR_FRACTION = 0.90    # share of a source's flows routed CLEAR
WIDE_FANOUT_DSTS = 20           # distinct destinations that count as wide fan-out

_SET_CAP = 1000  # stop growing per-source sets here; counts above this are not needed

OUTCOME_CONFIRM = "NO_FLAGS"
OUTCOME_REVIEW = "FLAGGED"

PARAMETERS = {
    "min_corroboration": MIN_CORROBORATION,
    "mostly_clear_fraction": MOSTLY_CLEAR_FRACTION,
    "wide_fanout_dsts": WIDE_FANOUT_DSTS,
}


def source_stats(scored_path: str | Path) -> dict[str, dict[str, Any]]:
    """Per-source route counts and distinct destinations/ports from a scored JSONL."""
    stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"total": 0, "clear": 0, "slow": 0, "fast": 0, "dsts": set(), "ports": set()}
    )
    with open(scored_path, encoding="utf-8") as source:
        for line in source:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            src = row.get("src_ip", row.get("source_ip"))
            if src is None:
                continue
            entry = stats[str(src)]
            entry["total"] += 1
            route = row.get("route")
            if route == "CLEAR":
                entry["clear"] += 1
            elif route == "SLOW_BRAIN":
                entry["slow"] += 1
            elif route == "FAST_TRACK":
                entry["fast"] += 1
            dst = row.get("dst_ip", row.get("dest_ip"))
            if dst is not None and len(entry["dsts"]) < _SET_CAP:
                entry["dsts"].add(str(dst))
            port = row.get("dst_port")
            if port is not None and len(entry["ports"]) < _SET_CAP:
                entry["ports"].add(port)
    return stats


def rule_check(
    *,
    src: str | None,
    s_score: float | None,
    upper: float | None,
    stats: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Apply the rules to one FAST_TRACK flow and return a JSON-serialisable result."""
    verdicts: list[str] = []
    flags: list[str] = []

    # 1. score against the approved upper threshold
    margin: float | None = None
    if s_score is None or upper is None:
        verdicts.append("score_above_upper_threshold: INSUFFICIENT (score or threshold missing)")
        flags.append("score_unavailable")
    else:
        margin = float(s_score) - float(upper)
        if margin >= 0:
            verdicts.append(
                f"score_above_upper_threshold: SUPPORTED (score {float(s_score):.4f}, "
                f"upper {float(upper):.4f}, margin {margin:+.4f})"
            )
        else:
            verdicts.append(
                f"score_above_upper_threshold: NOT_SUPPORTED (margin {margin:+.4f})"
            )
            flags.append("score_below_recorded_threshold")

    # 2. other flows from the same source in the scored file
    context: dict[str, Any] = {}
    if not stats:
        verdicts.append("source_context: INSUFFICIENT (source not found in scored file)")
        flags.append("source_context_unavailable")
    else:
        total, clear = int(stats["total"]), int(stats["clear"])
        slow, fast = int(stats["slow"]), int(stats["fast"])
        clear_fraction = clear / total if total else 0.0
        context = {
            "flows_total": total,
            "flows_clear": clear,
            "flows_slow_brain": slow,
            "flows_fast_track": fast,
            "distinct_destinations": len(stats["dsts"]),
            "distinct_dst_ports": len(stats["ports"]),
            "clear_fraction": round(clear_fraction, 4),
        }

        if fast >= MIN_CORROBORATION:
            verdicts.append(
                f"source_corroboration: SUPPORTED ({fast} FAST_TRACK flows from this source)"
            )
        else:
            verdicts.append(
                f"source_corroboration: WEAK ({fast} FAST_TRACK flow(s) from this source)"
            )
            if slow == 0:
                flags.append("isolated_flow(no_other_escalated_flows_from_source)")

        if clear_fraction >= MOSTLY_CLEAR_FRACTION:
            flags.append(f"source_mostly_clear({clear_fraction:.0%} of its flows were CLEAR)")
        verdicts.append(
            f"source_escalation_share: {fast + slow} of {total} flows escalated "
            f"({(fast + slow) / total:.0%})" if total else "source_escalation_share: n/a"
        )

        if len(stats["dsts"]) >= WIDE_FANOUT_DSTS:
            verdicts.append(
                f"fan_out: {len(stats['dsts'])} distinct destinations "
                "(consistent with scanning or sweeping; heuristic)"
            )

    ok = not flags
    return {
        "check_type": CHECK_TYPE,
        "rules_version": RULES_VERSION,
        "status": "OK",
        "outcome": OUTCOME_CONFIRM if ok else OUTCOME_REVIEW,
        "priority_recommendation": "no_flags" if ok else "flagged",
        "reasons": [
            "rule_based_check_no_llm",
            "priority_unchanged_fast_track_is_high",
        ],
        "verdicts": verdicts,
        "gate_flags": flags,
        "score_margin": None if margin is None else round(margin, 6),
        "source_context": context,
        "parameters": dict(PARAMETERS),
        "note": (
            "Rule-based heuristics, not the LLM verifier or risk gate. "
            "Parameters are uncalibrated. The dataset label is not used."
        ),
    }


def apply_to_store(db_path: str | Path, scored_path: str | Path) -> dict[str, Any]:
    """Add ``evidence["rule_check"]`` to every fast_track incident in a store.

    Safe to repeat: the check is recomputed and replaced. Priority, route and every other
    column are left untouched.
    """
    stats = source_stats(scored_path)
    outcomes: Counter[str] = Counter()
    updated = skipped = 0
    with closing(sqlite3.connect(str(db_path), timeout=5.0)) as conn:
        rows = conn.execute(
            "SELECT incident_id, src, s_score, evidence, thresholds "
            "FROM incidents WHERE kind = 'fast_track'"
        ).fetchall()
        for incident_id, src, s_score, evidence_json, thresholds_json in rows:
            try:
                evidence = json.loads(evidence_json) if evidence_json else {}
                thresholds = json.loads(thresholds_json) if thresholds_json else {}
                if not isinstance(evidence, dict):
                    raise ValueError("evidence is not an object")
            except (json.JSONDecodeError, ValueError):
                skipped += 1
                continue
            upper = thresholds.get("upper") if isinstance(thresholds, dict) else None
            result = rule_check(
                src=src,
                s_score=s_score,
                upper=upper,
                stats=stats.get(str(src)) if src is not None else None,
            )
            evidence["rule_check"] = result
            conn.execute(
                "UPDATE incidents SET evidence = ? WHERE incident_id = ?",
                (json.dumps(evidence, allow_nan=False, default=str), incident_id),
            )
            outcomes[result["outcome"]] += 1
            updated += 1
        conn.commit()
    return {"updated": updated, "skipped": skipped, "outcomes": dict(outcomes)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scored", type=Path, required=True, help="scored flows JSONL")
    parser.add_argument("--incident-db", type=Path, required=True, help="incident SQLite store")
    args = parser.parse_args()
    if not args.scored.is_file():
        raise SystemExit(f"scored file not found: {args.scored}")
    if not args.incident_db.is_file():
        raise SystemExit(f"incident store not found: {args.incident_db}")
    result = apply_to_store(args.incident_db, args.scored)
    print(f"fast-track rule check: {result}")


if __name__ == "__main__":
    main()