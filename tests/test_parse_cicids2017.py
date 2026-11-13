import json

import pytest

from tools.parse_cicids2017 import convert_csv


def test_converts_cicids2017_rows(tmp_path):
    source = tmp_path / "monday.csv"
    destination = tmp_path / "flows.jsonl"

    source.write_text(
        "Timestamp,Protocol,Flow Duration,Total Fwd Packet,"
        "Total Bwd packets,Total Length of Fwd Packet,"
        "Total Length of Bwd Packet,Label\n"
        "2017-07-03 08:00:00,6,125000,10,5,800,1200,BENIGN\n"
        "2017-07-03 08:00:01,17,2000000,4,6,400,600,DoS\n",
        encoding="utf-8",
    )

    written, skipped = convert_csv(source, destination)

    records = [
        json.loads(line)
        for line in destination.read_text(encoding="utf-8").splitlines()
    ]

    assert (written, skipped) == (2, 0)
    assert records[0] == {
        "flow_id": "cicids2017:monday:1",
        "packet_count": 15,
        "byte_count": 2000,
        "duration_ms": 125.0,
        "label": "benign",
        "timestamp": "2017-07-03 08:00:00",
        "protocol": "6",
    }
    assert records[1]["label"] == "dos"
    assert records[1]["duration_ms"] == 2000.0
    assert records[0]["flow_id"] != records[1]["flow_id"]


def test_skips_malformed_rows(tmp_path):
    source = tmp_path / "monday.csv"
    destination = tmp_path / "flows.jsonl"

    source.write_text(
        "Flow Duration,Total Fwd Packet,Total Bwd packets,"
        "Total Length of Fwd Packet,Total Length of Bwd Packet,Label\n"
        "1000,2,3,100,200,BENIGN\n"
        "invalid,2,3,100,200,BENIGN\n",
        encoding="utf-8",
    )

    written, skipped = convert_csv(source, destination)

    assert (written, skipped) == (1, 1)


def test_missing_required_header_fails(tmp_path):
    source = tmp_path / "monday.csv"
    destination = tmp_path / "flows.jsonl"
    source.write_text("Flow Duration,Label\n1000,BENIGN\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing required columns"):
        convert_csv(source, destination)


def test_rejects_same_input_and_output(tmp_path):
    source = tmp_path / "monday.csv"
    source.write_text("Flow Duration,Label\n1000,BENIGN\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must be different"):
        convert_csv(source, source)
