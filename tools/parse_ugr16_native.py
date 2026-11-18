#!/usr/bin/env python3
"""Convert the official UGR'16 labeled weekly CSV (headerless, 13 columns) to canonical JSONL.

Official column order (confirmed on real June and August 2016 samples):
    te, td, sa, da, sp, dp, pr, flg, fwd, stos, pkt, byt, label
    end-of-flow time (YYYY-MM-DD HH:MM:SS), duration in seconds, source IP, destination IP,
    source port, destination port, protocol, TCP flags, forwarding status, type of service,
    packets, bytes, label.

Notes (also written into each record's metadata):
  * The timestamp is the END of the flow, not its start.
  * The dataset states no time zone; it is written as UTC. Only differences between times
    are meaningful, not the absolute clock.
  * Labels are lower-cased (background, dos, scan11, scan44, nerisbotnet, blacklist, ...).
    "background" means "not proven to be an attack", not "verified benign".

This does not replace tools/parse_ugr16.py, which expects a CSV with a header row.
Do not feed whole weekly files through it; sample first (see docs). Pure standard library.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

N_COLUMNS = 13
MAX_PRINTED_SKIPS = 20


def parse_timestamp(text: str) -> str:
    moment = datetime.strptime(text.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return moment.isoformat().replace("+00:00", "Z")


def _count(text: str, name: str) -> int:
    value = text.strip()
    if not value.isdigit():
        raise ValueError(f"{name} is not a non-negative integer: {text!r}")
    return int(value)


def _port(text: str, name: str) -> int:
    value = _count(text, name)
    if value > 65535:
        raise ValueError(f"{name} must be 0..65535: {text!r}")
    return value


def convert_row(row: list[str], source_name: str, row_number: int) -> dict:
    if len(row) != N_COLUMNS:
        raise ValueError(f"expected {N_COLUMNS} columns, got {len(row)}")
    te, td, sa, da, sp, dp, pr, flg, fwd, stos, pkt, byt, label = (c.strip() for c in row)
    if not sa or not da:
        raise ValueError("source or destination address is empty")
    if not pr:
        raise ValueError("protocol is empty")
    if not label:
        raise ValueError("label is empty")
    try:
        duration_s = float(td)
    except ValueError as exc:
        raise ValueError(f"duration is not numeric: {td!r}") from exc
    if not (duration_s >= 0.0) or duration_s == float("inf"):
        raise ValueError(f"duration must be finite and non-negative: {td!r}")
    return {
        "flow_id": f"ugr16:{source_name}:{row_number}",
        "timestamp": parse_timestamp(te),
        "src_ip": sa,
        "dst_ip": da,
        "src_port": _port(sp, "source port"),
        "dst_port": _port(dp, "destination port"),
        "protocol": pr.lower(),
        "packets": _count(pkt, "packets"),
        "bytes": _count(byt, "bytes"),
        "duration_ms": duration_s * 1000.0,
        "label": label.lower(),
        "metadata": {
            "source_dataset": "UGR16",
            "source_file": source_name,
            "source_row": row_number,
            "original_timestamp": te,
            "timestamp_semantics": "wall_clock",
            "timestamp_is_wall_clock": True,
            "timestamp_meaning": "flow_end",
            "timezone_assumption": "UTC (dataset states no time zone)",
            "tcp_flags": flg,
            "forwarding_status": fwd,
            "type_of_service": stos,
        },
    }


def convert_csv(input_path: Path, output_path: Path, source_name: str | None = None,
                output: TextIO = sys.stderr) -> tuple[int, int]:
    if input_path.resolve() == output_path.resolve():
        raise ValueError("input and output paths must be different")
    name = source_name or input_path.stem
    written = skipped = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("r", encoding="utf-8", newline="") as source, \
            output_path.open("w", encoding="utf-8", newline="") as dest:
        for line_number, row in enumerate(csv.reader(source), start=1):
            if not row or (len(row) == 1 and not row[0].strip()):
                continue  # the official files can start with an empty line
            try:
                flow = convert_row(row, name, written + 1)
            except ValueError as exc:
                skipped += 1
                if skipped <= MAX_PRINTED_SKIPS:
                    print(f"skipping line {line_number}: {exc}", file=output)
                continue
            dest.write(json.dumps(flow, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
            dest.write("\n")
            written += 1
    if skipped > MAX_PRINTED_SKIPS:
        print(f"... and {skipped - MAX_PRINTED_SKIPS} more skipped lines not shown", file=output)
    return written, skipped


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Convert official headerless UGR'16 CSV to INTRUSCAN JSONL.")
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--source-name", help="used in flow_id; default is the input file name without extension. "
                   "Use a different name for every file so flow ids stay unique across TRAIN/CALIB/TEST")
    a = p.parse_args(argv)
    try:
        written, skipped = convert_csv(a.input, a.output, a.source_name)
    except (OSError, ValueError, csv.Error) as exc:
        print(f"UGR'16 conversion failed: {exc}", file=sys.stderr)
        return 1
    print(f"converted {written} rows; skipped {skipped} malformed lines", file=sys.stderr)
    print("Timestamps are flow END times, written as UTC without a stated source time zone.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
