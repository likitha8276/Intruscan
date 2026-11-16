"""Canonical flow record contract shared by Layer 1 (Go), the parsers and Layer 2.

This is the Python mirror of ``validateRecord`` / ``flowRecord`` in ``ingestion/main.go``.
``tests/test_flow_contract.py`` parses the Go struct tags and fails if the two drift apart.

Provenance is deliberately NOT part of a flow. ``provenance_signature`` is an HMAC over an
*event* (``soc_agent.provenance``) and is added by ``rag.bridge`` when it builds events from
scored flows, i.e. at the point where the pipeline itself (holding ``SOC_PROVENANCE_KEY``)
vouches for the event. A flow carrying that field is rejected like any other unknown field.

CLI: ``python -m soc_agent.flow_contract flows.jsonl`` exits 1 and lists the first problems.
"""

from __future__ import annotations

import json
import math
import sys
from collections.abc import Mapping
from datetime import datetime

REQUIRED_FIELDS: tuple[str, ...] = (
    "flow_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "packets", "bytes", "duration_ms",
)
OPTIONAL_FIELDS: tuple[str, ...] = ("label", "metadata", "features")
CANONICAL_FIELDS: frozenset[str] = frozenset(REQUIRED_FIELDS + OPTIONAL_FIELDS)

# Fields added downstream of ingestion; never present in an ingested flow.
SCORED_FIELDS: frozenset[str] = frozenset({"s_score", "route"})


def _is_int(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value) and value == int(value)


def _parse_rfc3339(text: str) -> None:
    # Go's time.RFC3339Nano requires an explicit zone; fromisoformat accepts 'Z' only on 3.11+.
    candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None:
        raise ValueError("no timezone offset")


def flow_problems(flow: object, *, allow_scored: bool = False) -> list[str]:
    """Return every contract violation for one record (empty list = valid)."""
    if not isinstance(flow, Mapping):
        return ["record must be a JSON object"]
    problems: list[str] = []
    allowed = CANONICAL_FIELDS | SCORED_FIELDS if allow_scored else CANONICAL_FIELDS
    for key in sorted(set(flow) - allowed):
        problems.append(f"unknown field {key!r}")
    for key in REQUIRED_FIELDS:
        if key not in flow or flow[key] is None:
            problems.append(f"{key} is required")
    for key in ("flow_id", "src_ip", "dst_ip", "protocol"):
        value = flow.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            problems.append(f"{key} must be a non-empty string")
    ts = flow.get("timestamp")
    if ts is not None:
        try:
            if not isinstance(ts, str):
                raise ValueError("not a string")
            _parse_rfc3339(ts)
        except ValueError as exc:
            problems.append(f"timestamp must be RFC3339 with a zone: {exc}")
    for key in ("src_port", "dst_port"):
        value = flow.get(key)
        if value is not None and not (_is_int(value) and 0 <= value <= 65535):
            problems.append(f"{key} must be an integer in 0..65535")
    for key in ("packets", "bytes"):
        value = flow.get(key)
        if value is not None and not (_is_int(value) and value >= 0):
            problems.append(f"{key} must be a non-negative integer")
    duration = flow.get("duration_ms")
    if duration is not None and (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration < 0
    ):
        problems.append("duration_ms must be a finite non-negative number")
    if "label" in flow and flow["label"] is not None and not isinstance(flow["label"], str):
        problems.append("label must be a string")
    if "metadata" in flow and flow["metadata"] is not None and not isinstance(flow["metadata"], Mapping):
        problems.append("metadata must be an object")
    features = flow.get("features")
    if features is not None:
        if not isinstance(features, Mapping):
            problems.append("features must be an object")
        else:
            for name, value in features.items():
                if not str(name).strip():
                    problems.append("feature names must not be empty")
                elif isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                    problems.append(f"feature {name!r} must be a non-negative number")
    return problems


def validate_flow(flow: object, *, allow_scored: bool = False) -> None:
    problems = flow_problems(flow, allow_scored=allow_scored)
    if problems:
        raise ValueError("; ".join(problems))


def check_jsonl(path: str, *, allow_scored: bool = False, limit: int = 20) -> list[str]:
    """Stream a JSONL file; return up to ``limit`` ``line N: problem`` strings."""
    found: list[str] = []
    with open(path, encoding="utf-8") as source:
        for number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                found.append(f"line {number}: invalid JSON: {exc}")
            else:
                found.extend(
                    f"line {number}: {p}" for p in flow_problems(record, allow_scored=allow_scored)
                )
            if len(found) >= limit:
                break
    return found


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    allow_scored = "--allow-scored" in args
    paths = [a for a in args if not a.startswith("--")]
    if not paths:
        print("usage: python -m soc_agent.flow_contract [--allow-scored] flows.jsonl", file=sys.stderr)
        return 2
    status = 0
    for path in paths:
        issues = check_jsonl(path, allow_scored=allow_scored)
        for issue in issues:
            print(f"{path}: {issue}", file=sys.stderr)
        status = status or (1 if issues else 0)
        if not issues:
            print(f"{path}: OK")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
