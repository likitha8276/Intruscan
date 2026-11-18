"""Reproducible end-to-end run: CSV/JSONL -> parser/archive -> Fast Brain (V2) -> RAG bridge ->
Slow Brain CLI (simulated LLM, real subprocess, signed events) -> incident store -> dashboard data.

Offline and deterministic: the MITRE index is a stub (no embedding download) and the LLM is the
built-in simulator. The Go ingester itself is covered by ingestion/main_test.go.
"""
import csv
import io
import json
import sqlite3
import sys

import pytest

from rag import handoff
from soc_agent import fast_brain_cli as fb
from soc_agent.flow_contract import check_jsonl
from soc_agent.incidents import IncidentStore
from tests.test_parse_cicids2017 import HEADER, sample
from tools.parse_cicids2017 import convert_csv
from dashboard import data as dash

KEY = "e2e-test-key"


class NoMitre:
    def query(self, text, k=8):
        return []


def _write_csv(path):
    rows = []
    for i in range(60):  # benign, wall-clock
        r = sample(f"2017-07-04 08:{i % 60:02d}:13.250")
        r.update({"Src Port": str(40000 + i), "Dst Port": "443", "Total Fwd Packet": str(8 + i % 5),
                  "Total Bwd packets": str(8 + i % 4), "Total Length of Fwd Packet": str(900 + 7 * i),
                  "Total Length of Bwd Packet": str(4000 + 11 * i), "Flow Duration": str(80000 + 900 * i)})
        rows.append(r)
    for i in range(14):  # one scanner hitting many ports with 1-packet flows
        r = sample(f"2017-07-04 09:00:{i:02d}.100")
        r.update({"Src IP dec": "3232238200", "Dst IP dec": "3232238083", "Src Port": "50000",
                  "Dst Port": str(20 + i), "Total Fwd Packet": "1", "Total Bwd packets": "0",
                  "Total Length of Fwd Packet": "44", "Total Length of Bwd Packet": "0",
                  "Flow Duration": "300", "Label": "PortScan"})
        rows.append(r)
    for i in range(2):  # relative-timestamp rows: must never reach the LLM
        r = sample("53:44.4")
        r.update({"Src IP dec": "3232238300", "Dst Port": str(30 + i), "Total Fwd Packet": "1",
                  "Total Bwd packets": "0", "Total Length of Fwd Packet": "44",
                  "Total Length of Bwd Packet": "0", "Flow Duration": "250", "Label": "PortScan"})
        rows.append(r)
    with path.open("w", newline="", encoding="utf-8") as h:
        w = csv.DictWriter(h, fieldnames=HEADER)
        w.writeheader()
        w.writerows(rows)


def _score_and_handoff(tmp_path, monkeypatch, parsed, *, archive=None):
    monkeypatch.setenv("SOC_PROVENANCE_KEY", KEY)
    model, scored = tmp_path / "m.joblib", tmp_path / "scored.jsonl"
    src = ["--archive", str(archive)] if archive else ["--input", str(parsed)]
    assert fb.main(["train", *src, "--model", str(model), "--feature-set", "v2"]) == 0
    assert fb.main(["score", *src, "--model", str(model), "--output", str(scored),
                    "--thresholds", str(tmp_path / "absent.json")]) == 0
    db = tmp_path / "inc.db"
    store = IncidentStore(db)
    from soc_agent.incidents import record_scored_file, run_context_from_model
    ctx = run_context_from_model(model)
    record_scored_file(str(scored), store, ctx, include_untimed=False)
    handoff.run(str(scored), tmp_path / "alerts.jsonl", NoMitre(), python=sys.executable,
                llm="sim", timeout=120, incident_store=store, run_context=ctx)
    return scored, store, ctx


def test_csv_to_dashboard_with_v2_signed_events_and_untimed_quarantine(tmp_path, monkeypatch):
    csv_path, parsed = tmp_path / "day.csv", tmp_path / "flows.jsonl"
    _write_csv(csv_path)
    assert convert_csv(csv_path, parsed, io.StringIO()) == (76, 0)
    assert check_jsonl(str(parsed)) == []                       # parser output meets the contract

    scored, store, ctx = _score_and_handoff(tmp_path, monkeypatch, parsed)
    assert ctx["feature_set"] == "v2"                           # V2 reaches the incident record

    rows = [json.loads(l) for l in scored.read_text().splitlines()]
    assert len(rows) == 76 and all(r["route"] in {"CLEAR", "SLOW_BRAIN", "FAST_TRACK"} for r in rows)
    assert all("metadata" in r and r["metadata"]["timestamp_is_wall_clock"] in (True, False) for r in rows)

    incidents = store.list()
    assert incidents, "no incidents were recorded"
    kinds = {i["kind"] for i in incidents}
    alerts = [json.loads(l) for l in (tmp_path / "alerts.jsonl").read_text().splitlines()]
    for a in alerts:                                            # real CLI ran; signatures verified
        assert a["soc_result"]["status"] == "OK", a["soc_result"]
    surrogate = {r["flow_id"] for r in rows if not r["metadata"]["timestamp_is_wall_clock"]}
    sent = {eid for a in alerts for eid in a["event_ids"]}
    assert not (surrogate & sent)                               # untimed flows never reach the LLM

    frame = dash.load_scored_flows(scored).frame
    assert len(frame) == 76 and set(dash.route_counts(frame)) <= {"CLEAR", "SLOW_BRAIN", "FAST_TRACK"}
    assert kinds


def test_go_archive_path_matches_jsonl_path(tmp_path, monkeypatch):
    """Go-written archive (same schema, raw_json preserved) scores identically to the JSONL."""
    csv_path, parsed = tmp_path / "day.csv", tmp_path / "flows.jsonl"
    _write_csv(csv_path)
    convert_csv(csv_path, parsed, io.StringIO())
    archive = tmp_path / "archive.db"
    with sqlite3.connect(archive) as c:
        c.execute("""CREATE TABLE flow_archive (flow_id TEXT PRIMARY KEY, timestamp DATETIME NOT NULL,
            src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, src_port INTEGER NOT NULL, dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL,
            duration_ms REAL NOT NULL, label TEXT, raw_json BLOB NOT NULL)""")
        for line in parsed.read_text().splitlines():
            f = json.loads(line)
            c.execute("INSERT INTO flow_archive VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (f["flow_id"], f["timestamp"], f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"],
                       f["protocol"], f["packets"], f["bytes"], f["duration_ms"], f["label"], line))
    scored_a, _, _ = _score_and_handoff(tmp_path, monkeypatch, parsed, archive=archive)
    arch_rows = {json.loads(l)["flow_id"]: json.loads(l) for l in scored_a.read_text().splitlines()}
    tmp2 = tmp_path / "b"
    tmp2.mkdir()
    scored_b, _, _ = _score_and_handoff(tmp2, monkeypatch, parsed)
    jsonl_rows = {json.loads(l)["flow_id"]: json.loads(l) for l in scored_b.read_text().splitlines()}
    assert arch_rows.keys() == jsonl_rows.keys()
    for fid, row in arch_rows.items():
        assert row["route"] == jsonl_rows[fid]["route"]
        assert row["s_score"] == pytest.approx(jsonl_rows[fid]["s_score"])
        assert row["metadata"] == jsonl_rows[fid]["metadata"]   # wall-clock flag survives the archive
