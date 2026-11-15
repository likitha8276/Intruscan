import csv, json
import pytest
from tools.parse_cicids2017 import convert_csv, convert_row, parse_timestamp

HEADER=["Src IP dec","Src Port","Dst IP dec","Dst Port","Protocol","Timestamp","Flow Duration",
"Total Fwd Packet","Total Bwd packets","Total Length of Fwd Packet","Total Length of Bwd Packet",
"Flow Bytes/s","Flow Packets/s","Fwd Packets/s","Bwd Packets/s","Fwd Packet Length Mean",
"Bwd Packet Length Mean","Packet Length Std","Flow IAT Mean","Flow IAT Std","SYN Flag Count",
"RST Flag Count","ACK Flag Count","Label","Attempted Category"]
def sample(timestamp="53:44.4"):
    return dict(zip(HEADER,["3232238085","49159","3232238083","445","6",timestamp,"90030854",
    "10","10","8","2","0.111073033","0.222146066","0.111073033","0.111073033","0.8","0.2",
    "0.512989176","4738466","11232767.18","0","0","20","BENIGN","-1"]))

def test_actual_cicids_row_maps_to_canonical_schema():
    f=convert_row(sample(),"tuesday",1)
    assert (f["src_ip"],f["dst_ip"])==("192.168.10.5","192.168.10.3")
    assert (f["src_port"],f["dst_port"],f["protocol"])==(49159,445,"6")
    assert (f["packets"],f["bytes"])==(20,10)
    assert f["duration_ms"]==pytest.approx(90030.854)
    assert len(f["features"])==20 and f["features"]["ack_flag_count"]==20
    assert f["metadata"]["original_timestamp"]=="53:44.4"
    assert f["metadata"]["timestamp_is_wall_clock"] is False
    assert f["label"]=="benign"

def test_full_timestamp():
    ts,kind=parse_timestamp("2017-07-04 08:12:13.250")
    assert ts=="2017-07-04T08:12:13.250000Z" and kind=="wall_clock"

def test_relative_timestamp_explicitly_marked():
    ts,kind=parse_timestamp("53:44.4")
    assert ts=="1970-01-01T00:53:44.400000Z" and kind=="relative_elapsed_surrogate"

def test_invalid_optional_feature_zero_filled_and_recorded():
    row=sample(); row["Flow Bytes/s"]="Infinity"
    f=convert_row(row,"tuesday",1)
    assert f["features"]["flow_bytes_per_second"]==0
    assert "flow_bytes_per_second" in f["metadata"]["zero_filled_missing_or_invalid_features"]

def test_jsonl_conversion(tmp_path):
    src=tmp_path/"tuesday.csv"; dst=tmp_path/"flows.jsonl"
    with src.open("w",newline="",encoding="utf-8") as h:
        w=csv.DictWriter(h,fieldnames=HEADER); w.writeheader(); w.writerow(sample())
    assert convert_csv(src,dst)==(1,0)
    obj=json.loads(dst.read_text().splitlines()[0])
    assert obj["src_ip"]=="192.168.10.5" and len(obj["features"])==20

def test_invalid_required_row_skipped(tmp_path):
    src=tmp_path/"tuesday.csv"; dst=tmp_path/"flows.jsonl"
    row=sample(); row["Src IP dec"]="bad"
    with src.open("w",newline="",encoding="utf-8") as h:
        w=csv.DictWriter(h,fieldnames=HEADER); w.writeheader(); w.writerow(row)
    assert convert_csv(src,dst)==(0,1)

def test_same_path_rejected(tmp_path):
    p=tmp_path/"same.csv"; p.write_text("header\n")
    with pytest.raises(ValueError,match="must be different"): convert_csv(p,p)
