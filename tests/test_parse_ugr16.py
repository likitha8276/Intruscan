import csv
import json

import pytest

from tools.parse_ugr16 import convert_csv


def test_converts_ugr16_rows_and_skips_malformed_row(tmp_path):
    source = tmp_path / "ugr.csv"
    destination = tmp_path / "flows.jsonl"
    source.write_text(
        "StartTime,Dur,Proto,SrcAddr,Sport,DstAddr,Dport,TotPkts,TotBytes,Label\n"
        '2016-01-01 00:00:00,0.125,TCP,192.0.2.1,1234,198.51.100.2,443,10,8000,background\n'
        '2016-01-01 00:00:01,0.2,UDP,192.0.2.3,1,198.51.100.4,53,not-a-count,900,scan\n',
        encoding="utf-8",
    )

    written, skipped = convert_csv(source, destination, None, {}, "seconds")

    assert (written, skipped) == (1, 1)
    record = json.loads(destination.read_text(encoding="utf-8"))
    assert record == {
        "flow_id": "flow_000001",
        "timestamp": "2016-01-01 00:00:00",
        "source_ip": "192.0.2.1",
        "dest_ip": "198.51.100.2",
        "protocol": "TCP",
        "byte_count": 8000,
        "packet_count": 10,
        "label": "background",
        "duration_ms": 125.0,
    }


def test_preserves_label_and_reads_comma_separated_counts(tmp_path):
    source = tmp_path / "ugr.csv"
    destination = tmp_path / "flows.jsonl"
    with source.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["src_ip", "dst_ip", "protocol", "bytes", "packets", "label"]
        )
        writer.writerow(["192.0.2.1", "198.51.100.2", "6", "1,024", "8.0", " scan "])

    written, skipped = convert_csv(source, destination, ",", {}, "seconds")

    assert (written, skipped) == (1, 0)
    record = json.loads(destination.read_text(encoding="utf-8"))
    assert record["byte_count"] == 1024
    assert record["packet_count"] == 8
    assert record["label"] == " scan "
    assert "duration_ms" not in record


def test_missing_required_header_fails_before_output(tmp_path):
    source = tmp_path / "ugr.csv"
    destination = tmp_path / "flows.jsonl"
    source.write_text("SrcAddr,DstAddr,Proto\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing required columns"):
        convert_csv(source, destination, ",", {}, "seconds")
