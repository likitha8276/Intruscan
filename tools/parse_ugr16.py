#!/usr/bin/env python3
"""Stream UGR'16 flow CSV rows into the Intruscan canonical JSONL format."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TextIO


COLUMN_ALIASES = {
    "timestamp": ("starttime", "timestamp", "ts", "firstseen", "flowstart"),
    "source_ip": ("srcaddr", "srcip", "sourceip", "sourceaddress"),
    "dest_ip": ("dstaddr", "dstip", "destinationip", "destinationaddress"),
    "protocol": ("proto", "protocol"),
    "byte_count": ("totbytes", "totalbytes", "bytecount", "bytes"),
    "packet_count": ("totpkts", "totalpackets", "packetcount", "packets", "pkts"),
    "label": ("label", "class", "category", "attacklabel"),
    "duration": ("dur", "duration", "durationseconds", "durationms"),
}
_HEADER_NORMALIZER = re.compile(r"[^a-z0-9]")


def normalize_header(value: str) -> str:
    return _HEADER_NORMALIZER.sub("", value.strip().lower())


def resolve_columns(
    header: list[str],
    overrides: dict[str, str],
) -> dict[str, str | None]:
    normalized = {normalize_header(name): name for name in header}
    resolved: dict[str, str | None] = {}
    for field, aliases in COLUMN_ALIASES.items():
        override = overrides.get(field)
        if override is not None:
            if override not in header:
                raise ValueError(
                    f"column override for {field!r} names missing header {override!r}"
                )
            resolved[field] = override
            continue
        resolved[field] = next(
            (normalized[alias] for alias in aliases if alias in normalized),
            None,
        )

    missing = [
        field
        for field in ("source_ip", "dest_ip", "protocol", "byte_count", "packet_count", "label")
        if resolved[field] is None
    ]
    if missing:
        raise ValueError(
            "CSV is missing required columns for "
            + ", ".join(missing)
            + "; use the --*-column options to map this file's headers"
        )
    return resolved


def parse_integer(value: str | None, field: str) -> int:
    if value is None or not value.strip():
        raise ValueError(f"{field} is empty")
    try:
        number = Decimal(value.strip().replace(",", ""))
    except InvalidOperation as exc:
        raise ValueError(f"{field} is not numeric: {value!r}") from exc
    if (
        not number.is_finite()
        or number != number.to_integral_value()
        or number < 0
        or number > 2**63 - 1
    ):
        raise ValueError(f"{field} must be a non-negative 64-bit integer: {value!r}")
    return int(number)


def parse_duration_ms(value: str | None, unit: str) -> float:
    if value is None or not value.strip():
        raise ValueError("duration is empty")
    try:
        duration = Decimal(value.strip())
    except InvalidOperation as exc:
        raise ValueError(f"duration is not numeric: {value!r}") from exc
    if not duration.is_finite() or duration < 0:
        raise ValueError(f"duration must be finite and non-negative: {value!r}")
    multiplier = Decimal(1000) if unit == "seconds" else Decimal(1)
    milliseconds = float(duration * multiplier)
    if milliseconds == float("inf"):
        raise ValueError(f"duration is too large: {value!r}")
    return milliseconds


def convert_row(
    row: dict[str | None, str | None],
    columns: dict[str, str | None],
    flow_number: int,
    duration_unit: str,
) -> dict[str, str | int | float]:
    source_ip = row.get(columns["source_ip"])
    dest_ip = row.get(columns["dest_ip"])
    protocol = row.get(columns["protocol"])
    label = row.get(columns["label"])
    if source_ip is None or not source_ip.strip():
        raise ValueError("source_ip is empty")
    if dest_ip is None or not dest_ip.strip():
        raise ValueError("dest_ip is empty")
    if protocol is None or not protocol.strip():
        raise ValueError("protocol is empty")
    if label is None or not label.strip():
        raise ValueError("label is empty")

    flow: dict[str, str | int | float] = {
        "flow_id": f"flow_{flow_number:06d}",
        "source_ip": source_ip.strip(),
        "dest_ip": dest_ip.strip(),
        "protocol": protocol.strip(),
        "byte_count": parse_integer(row.get(columns["byte_count"]), "byte_count"),
        "packet_count": parse_integer(row.get(columns["packet_count"]), "packet_count"),
        "label": label,
    }
    if columns["timestamp"] is not None:
        timestamp = row.get(columns["timestamp"])
        if timestamp is None or not timestamp.strip():
            raise ValueError("timestamp is empty")
        flow["timestamp"] = timestamp.strip()
    if columns["duration"] is not None:
        unit = duration_unit
        if unit == "auto":
            unit = (
                "milliseconds"
                if normalize_header(columns["duration"]).endswith("ms")
                else "seconds"
            )
        flow["duration_ms"] = parse_duration_ms(
            row.get(columns["duration"]), unit
        )
    return flow


def convert_csv(
    input_path: Path,
    output_path: Path,
    delimiter: str | None,
    overrides: dict[str, str],
    duration_unit: str,
    output: TextIO = sys.stderr,
) -> tuple[int, int]:
    written = 0
    skipped = 0
    if input_path.resolve() == output_path.resolve():
        raise ValueError("input and output paths must be different")
    with input_path.open("r", encoding="utf-8-sig", newline="") as source:
        sample = source.read(64 * 1024)
        source.seek(0)
        if delimiter is None:
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                delimiter = dialect.delimiter
            except csv.Error:
                delimiter = ","

        reader = csv.DictReader(source, delimiter=delimiter)
        if reader.fieldnames is None:
            raise ValueError("CSV has no header row")
        columns = resolve_columns(reader.fieldnames, overrides)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="") as destination:
            for row in reader:
                try:
                    if None in row:
                        raise ValueError("row has more fields than the CSV header")
                    flow = convert_row(row, columns, written + 1, duration_unit)
                    destination.write(
                        json.dumps(
                            flow,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            allow_nan=False,
                        )
                    )
                    destination.write("\n")
                    written += 1
                except (ValueError, TypeError) as exc:
                    skipped += 1
                    print(
                        f"skipping CSV row ending at line {reader.line_num}: {exc}",
                        file=output,
                    )
    return written, skipped


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert UGR'16 CSV flows to streaming canonical JSONL."
    )
    parser.add_argument("input", type=Path, help="input UGR'16 CSV file")
    parser.add_argument(
        "output",
        type=Path,
        help="output JSONL file (for example ugr16_flows.jsonl)",
    )
    parser.add_argument(
        "--delimiter",
        choices=[",", ";", "\\t", "|"],
        help="CSV delimiter (auto-detected by default)",
    )
    parser.add_argument(
        "--duration-unit",
        choices=("auto", "seconds", "milliseconds"),
        default="auto",
        help="duration unit (auto uses ms suffix; otherwise defaults to seconds)",
    )
    for field, option in (
        ("timestamp", "--timestamp-column"),
        ("source_ip", "--source-ip-column"),
        ("dest_ip", "--dest-ip-column"),
        ("protocol", "--protocol-column"),
        ("byte_count", "--byte-count-column"),
        ("packet_count", "--packet-count-column"),
        ("label", "--label-column"),
        ("duration", "--duration-column"),
    ):
        parser.add_argument(option, dest=field, help=f"override detected {field} column")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    delimiter = "\t" if args.delimiter == "\\t" else args.delimiter
    overrides = {
        field: getattr(args, field)
        for field in COLUMN_ALIASES
        if getattr(args, field) is not None
    }
    try:
        written, skipped = convert_csv(
            args.input,
            args.output,
            delimiter,
            overrides,
            args.duration_unit,
        )
    except (OSError, ValueError, csv.Error) as exc:
        print(f"UGR'16 conversion failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"converted {written} rows; skipped {skipped} malformed rows",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
