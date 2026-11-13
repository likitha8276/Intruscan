#!/usr/bin/env python3
"""Convert CICIDS2017 flow CSV files into INTRUSCAN canonical JSONL."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TextIO


REQUIRED_COLUMNS = (
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "Label",
)
V2_COLUMN_MAP = {
    "Total Fwd Packet": "fwd_packets",
    "Total Bwd packets": "bwd_packets",
    "Total Length of Fwd Packet": "fwd_bytes",
    "Total Length of Bwd Packet": "bwd_bytes",
    "Flow Bytes/s": "flow_bytes_per_second",
    "Flow Packets/s": "flow_packets_per_second",
    "Fwd Packets/s": "fwd_packets_per_second",
    "Bwd Packets/s": "bwd_packets_per_second",
    "Fwd Packet Length Mean": "fwd_packet_length_mean",
    "Bwd Packet Length Mean": "bwd_packet_length_mean",
    "Packet Length Std": "packet_length_std",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "ACK Flag Count": "ack_flag_count",
}


def parse_number(value: str | None, field: str) -> Decimal:
    if value is None or not value.strip():
        raise ValueError(f"{field} is empty")
    try:
        number = Decimal(value.strip())
    except InvalidOperation as exc:
        raise ValueError(f"{field} is not numeric: {value!r}") from exc
    if not number.is_finite() or number < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return number


def parse_count(value: str | None, field: str) -> int:
    number = parse_number(value, field)
    if number != number.to_integral_value() or number > 2**63 - 1:
        raise ValueError(f"{field} must be a non-negative 64-bit integer")
    return int(number)


def convert_row(
    row: dict[str | None, str | None],
    source_name: str,
    row_number: int,
) -> dict:
    if None in row:
        raise ValueError("row has more fields than the CSV header")

    label = row.get("Label")
    if label is None or not label.strip():
        raise ValueError("Label is empty")

    packets = (
        parse_count(row.get("Total Fwd Packet"), "Total Fwd Packet")
        + parse_count(row.get("Total Bwd packets"), "Total Bwd packets")
    )
    byte_count = (
        parse_count(row.get("Total Length of Fwd Packet"),
                    "Total Length of Fwd Packet")
        + parse_count(row.get("Total Length of Bwd Packet"),
                      "Total Length of Bwd Packet")
    )

    duration_us = parse_number(row.get("Flow Duration"), "Flow Duration")
    duration_ms = float(duration_us / Decimal(1000))
    if not duration_ms < float("inf"):
        raise ValueError("duration is too large")

    flow = {
        "flow_id": f"cicids2017:{source_name}:{row_number}",
        "packet_count": packets,
        "byte_count": byte_count,
        "duration_ms": duration_ms,
        "label": label.strip().lower(),
    }

    timestamp = row.get("Timestamp")
    if timestamp and timestamp.strip():
        flow["timestamp"] = timestamp.strip()

    protocol = row.get("Protocol")
    if protocol and protocol.strip():
        flow["protocol"] = protocol.strip()

    return flow


def convert_csv(
    input_path: Path,
    output_path: Path,
    output: TextIO = sys.stderr,
) -> tuple[int, int]:
    if input_path.resolve() == output_path.resolve():
        raise ValueError("input and output paths must be different")

    written = 0
    skipped = 0

    with input_path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)

        if reader.fieldnames is None:
            raise ValueError("CSV has no header row")

        missing = [name for name in REQUIRED_COLUMNS
                   if name not in reader.fieldnames]
        if missing:
            raise ValueError("CSV is missing required columns: " + ", ".join(missing))

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8", newline="") as destination:
            for row_number, row in enumerate(reader, start=1):
                try:
                    flow = convert_row(row, input_path.stem, row_number)
                    destination.write(
                        json.dumps(flow, separators=(",", ":"), allow_nan=False)
                        + "\n"
                    )
                    written += 1
                except (ValueError, TypeError) as exc:
                    skipped += 1
                    print(
                        f"Skipping CSV row ending at line {reader.line_num}: {exc}",
                        file=output,
                    )

    return written, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert CICIDS2017 CSV flows to canonical JSONL."
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)

    try:
        written, skipped = convert_csv(args.input, args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Converted {written} flows; skipped {skipped} rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
