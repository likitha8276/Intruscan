"""Official headerless UGR'16 CSV -> canonical JSONL (tools/parse_ugr16_native.py).

Fixture rows are real lines from the official june_week4 (calibration) and august_week5 (test)
files, which have no header row and can start with an empty line.
"""
import json

import pytest

from soc_agent.features import extract_features
from soc_agent.flow_contract import flow_problems
from tools.parse_ugr16_native import convert_csv, convert_row

JUNE = "2016-06-20 00:06:55,2.856,42.219.159.90,83.107.168.102,36351,445,TCP,....S.,0,0,2,96,background"
AUG = "2016-08-29 00:12:21,0.000,143.72.4.250,42.219.147.178,53,28627,UDP,.A....,0,0,1,148,background"


def _convert(tmp_path, text, name="ugr_test"):
    src = tmp_path / f"{name}.csv"
    dst = tmp_path / "out.jsonl"
    src.write_text(text, encoding="utf-8")
    written, skipped = convert_csv(src, dst)
    return written, skipped, [json.loads(line) for line in dst.read_text(encoding="utf-8").splitlines()]


def test_real_rows_become_valid_canonical_flows(tmp_path):
    written, skipped, flows = _convert(tmp_path, f"\n{JUNE}\n{AUG}\n")  # leading empty line
    assert (written, skipped) == (2, 0)
    june, aug = flows
    assert june["timestamp"] == "2016-06-20T00:06:55Z"
    assert june["duration_ms"] == pytest.approx(2856.0)
    assert (june["src_port"], june["dst_port"], june["protocol"]) == (36351, 445, "tcp")
    assert (june["packets"], june["bytes"], june["label"]) == (2, 96, "background")
    assert aug["protocol"] == "udp" and aug["duration_ms"] == 0.0
    for flow in flows:
        assert flow_problems(flow) == []


def test_metadata_is_honest_about_time(tmp_path):
    _, _, flows = _convert(tmp_path, JUNE + "\n")
    meta = flows[0]["metadata"]
    assert meta["timestamp_is_wall_clock"] is True
    assert meta["timestamp_meaning"] == "flow_end"
    assert meta["original_timestamp"] == "2016-06-20 00:06:55"
    assert "UTC" in meta["timezone_assumption"]
    assert meta["tcp_flags"] == "....S."


def test_flow_ids_differ_between_files_and_rows(tmp_path):
    _, _, a = _convert(tmp_path, JUNE + "\n" + JUNE + "\n", name="train")
    _, _, b = _convert(tmp_path, JUNE + "\n", name="test")
    ids = [f["flow_id"] for f in a + b]
    assert len(set(ids)) == 3


def test_malformed_lines_are_skipped_and_counted(tmp_path):
    bad_ts = JUNE.replace("2016-06-20", "20-06-2016")
    bad_port = JUNE.replace(",445,", ",70000,")
    short = "1,2,3"
    written, skipped, flows = _convert(tmp_path, "\n".join([JUNE, bad_ts, bad_port, short, AUG]) + "\n")
    assert (written, skipped) == (2, 3)
    assert [f["label"] for f in flows] == ["background", "background"]


def test_output_is_accepted_by_v2_features(tmp_path):
    _, _, flows = _convert(tmp_path, JUNE + "\n" + AUG + "\n")
    for flow in flows:
        assert extract_features(flow, "v2").shape == (11,)


def test_convert_row_rejects_wrong_column_count():
    with pytest.raises(ValueError):
        convert_row(JUNE.split(",")[:-1], "x", 1)
