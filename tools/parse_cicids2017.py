#!/usr/bin/env python3
"""CICIDS2017 CSV -> INTRUSCAN canonical JSONL with Fast Brain V2 features."""
from __future__ import annotations
import argparse, csv, ipaddress, json, math, re, sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import TextIO

REQUIRED_COLUMNS = ("Src IP dec","Src Port","Dst IP dec","Dst Port","Protocol","Timestamp",
"Flow Duration","Total Fwd Packet","Total Bwd packets","Total Length of Fwd Packet",
"Total Length of Bwd Packet","Label")
V2_COLUMN_MAP = {
"Total Fwd Packet":"fwd_packets","Total Bwd packets":"bwd_packets",
"Total Length of Fwd Packet":"fwd_bytes","Total Length of Bwd Packet":"bwd_bytes",
"Flow Bytes/s":"flow_bytes_per_second","Flow Packets/s":"flow_packets_per_second",
"Fwd Packets/s":"fwd_packets_per_second","Bwd Packets/s":"bwd_packets_per_second",
"Fwd Packet Length Mean":"fwd_packet_length_mean","Bwd Packet Length Mean":"bwd_packet_length_mean",
"Packet Length Std":"packet_length_std","Flow IAT Mean":"flow_iat_mean",
"Flow IAT Std":"flow_iat_std","SYN Flag Count":"syn_flag_count",
"RST Flag Count":"rst_flag_count","ACK Flag Count":"ack_flag_count"}
V2_FEATURE_NAMES = ("total_packets","total_bytes","duration_ms","mean_packet_size",
"fwd_packets","bwd_packets","fwd_bytes","bwd_bytes","flow_bytes_per_second",
"flow_packets_per_second","fwd_packets_per_second","bwd_packets_per_second",
"fwd_packet_length_mean","bwd_packet_length_mean","packet_length_std",
"flow_iat_mean","flow_iat_std","syn_flag_count","rst_flag_count","ack_flag_count")
RELATIVE_RE = re.compile(r"^(\d+):(\d{1,2}(?:\.\d+)?)$")

def parse_number(value, field):
    if value is None or not str(value).strip(): raise ValueError(f"{field} is empty")
    try: n = Decimal(str(value).strip())
    except InvalidOperation as e: raise ValueError(f"{field} is not numeric: {value!r}") from e
    if not n.is_finite() or n < 0: raise ValueError(f"{field} must be finite and non-negative")
    return n

def parse_count(value, field):
    n = parse_number(value, field)
    if n != n.to_integral_value() or n > 2**63-1: raise ValueError(f"{field} must be a non-negative 64-bit integer")
    return int(n)

def parse_ip_decimal(value, field):
    n = parse_count(value, field)
    if n > 0xffffffff: raise ValueError(f"{field} is outside IPv4 integer range")
    return str(ipaddress.IPv4Address(n))

def parse_timestamp(value):
    if value is None or not value.strip(): raise ValueError("Timestamp is empty")
    raw = value.strip()
    try:
        dt = datetime.fromisoformat(raw.replace("Z","+00:00"))
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z"), "wall_clock"
    except ValueError: pass
    m = RELATIVE_RE.fullmatch(raw)
    if not m: raise ValueError(f"unsupported Timestamp format: {raw!r}")
    sec = Decimal(m.group(2))
    if sec >= 60: raise ValueError(f"relative Timestamp seconds must be below 60: {raw!r}")
    dt = datetime(1970,1,1,tzinfo=timezone.utc) + timedelta(minutes=int(m.group(1)),seconds=float(sec))
    return dt.isoformat(timespec="microseconds").replace("+00:00","Z"), "relative_elapsed_surrogate"

def optional_feature(row, col, name, missing):
    raw = row.get(col)
    try:
        if raw is None or not raw.strip(): raise ValueError()
        n = float(Decimal(raw.strip()))
        if not math.isfinite(n) or n < 0: raise ValueError()
        return n
    except (InvalidOperation, ValueError, OverflowError):
        missing.append(name); return 0.0

def convert_row(row, source_name, row_number):
    if None in row: raise ValueError("row has more fields than CSV header")
    label = row.get("Label")
    if label is None or not label.strip(): raise ValueError("Label is empty")
    src_ip, dst_ip = parse_ip_decimal(row.get("Src IP dec"),"Src IP dec"), parse_ip_decimal(row.get("Dst IP dec"),"Dst IP dec")
    src_port, dst_port = parse_count(row.get("Src Port"),"Src Port"), parse_count(row.get("Dst Port"),"Dst Port")
    if src_port > 65535 or dst_port > 65535: raise ValueError("ports must be between 0 and 65535")
    protocol = row.get("Protocol")
    if protocol is None or not protocol.strip(): raise ValueError("Protocol is empty")
    fp = parse_count(row.get("Total Fwd Packet"),"Total Fwd Packet")
    bp = parse_count(row.get("Total Bwd packets"),"Total Bwd packets")
    fb = parse_count(row.get("Total Length of Fwd Packet"),"Total Length of Fwd Packet")
    bb = parse_count(row.get("Total Length of Bwd Packet"),"Total Length of Bwd Packet")
    packets, byte_count = fp+bp, fb+bb
    duration_ms = float(parse_number(row.get("Flow Duration"),"Flow Duration") / Decimal(1000))
    if not math.isfinite(duration_ms): raise ValueError("duration is too large")
    timestamp, ts_kind = parse_timestamp(row.get("Timestamp"))
    missing = []
    mapped = {}
    for col,name in V2_COLUMN_MAP.items():
        if name == "fwd_packets": mapped[name] = float(fp)
        elif name == "bwd_packets": mapped[name] = float(bp)
        elif name == "fwd_bytes": mapped[name] = float(fb)
        elif name == "bwd_bytes": mapped[name] = float(bb)
        else: mapped[name] = optional_feature(row,col,name,missing)
    features = {"total_packets":float(packets),"total_bytes":float(byte_count),
        "duration_ms":duration_ms,"mean_packet_size":byte_count/packets if packets else 0.0,**mapped}
    features = {k:features[k] for k in V2_FEATURE_NAMES}
    metadata = {"source_dataset":"CICIDS2017","source_file":source_name,"source_row":row_number,
        "original_timestamp":row.get("Timestamp","").strip(),"timestamp_semantics":ts_kind,
        "timestamp_is_wall_clock":ts_kind=="wall_clock",
        "attempted_category":(row.get("Attempted Category") or "").strip()}
    if missing: metadata["zero_filled_missing_or_invalid_features"] = sorted(set(missing))
    return {"flow_id":f"cicids2017:{source_name}:{row_number}","timestamp":timestamp,
        "src_ip":src_ip,"dst_ip":dst_ip,"src_port":src_port,"dst_port":dst_port,
        "protocol":protocol.strip(),"packets":packets,"bytes":byte_count,
        "duration_ms":duration_ms,"label":label.strip().lower(),"metadata":metadata,"features":features}

def convert_csv(input_path:Path, output_path:Path, output:TextIO=sys.stderr):
    if input_path.resolve()==output_path.resolve(): raise ValueError("input and output paths must be different")
    written=skipped=0
    with input_path.open("r",encoding="utf-8-sig",newline="") as src:
        reader=csv.DictReader(src)
        if reader.fieldnames is None: raise ValueError("CSV has no header row")
        missing=[x for x in REQUIRED_COLUMNS if x not in reader.fieldnames]
        if missing: raise ValueError("CSV is missing required columns: "+", ".join(missing))
        output_path.parent.mkdir(parents=True,exist_ok=True)
        with output_path.open("w",encoding="utf-8",newline="") as dst:
            for i,row in enumerate(reader,1):
                try:
                    obj=convert_row(row,input_path.stem,i)
                    dst.write(json.dumps(obj,separators=(",",":"),allow_nan=False)+"\n"); written+=1
                except (ValueError,TypeError) as e:
                    skipped+=1; print(f"Skipping CSV row ending at line {reader.line_num}: {e}",file=output)
    return written,skipped

def main(argv=None):
    p=argparse.ArgumentParser(description="Convert CICIDS2017 CSV flows to INTRUSCAN JSONL.")
    p.add_argument("input",type=Path); p.add_argument("output",type=Path); a=p.parse_args(argv)
    try: written,skipped=convert_csv(a.input,a.output)
    except (OSError,ValueError) as e: p.error(str(e))
    print(f"Converted {written} flows; skipped {skipped} rows.")
    print("Relative timestamp surrogates are not real wall-clock event times.")
    return 0
if __name__=="__main__": raise SystemExit(main())
