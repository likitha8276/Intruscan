import io
import json
import sqlite3

import joblib
import numpy as np

from soc_agent.fast_brain import EarlyExitMVIForest, features_from_flow
from soc_agent.fast_brain_cli import (
    score_archive,
    score_jsonl,
    train_archive,
    train_jsonl,
)


def _flow(flow_id, packets, bytes_, duration_ms, label):
    return {
        "flow_id": flow_id,
        "timestamp": "2026-11-03T10:00:00Z",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 51000,
        "dst_port": 443,
        "protocol": "tcp",
        "packets": packets,
        "bytes": bytes_,
        "duration_ms": duration_ms,
        "label": label,
    }


def _make_archive(path):
    with sqlite3.connect(path) as connection:
        connection.execute(
            """CREATE TABLE flow_archive (
                flow_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                label TEXT,
                raw_json BLOB NOT NULL
            )"""
        )
        flows = [
            _flow("benign-1", 10, 8000, 100, "benign"),
            _flow("benign-2", 12, 9000, 110, "benign"),
            _flow("attack-1", 10000, 8000000, 5, "attack"),
        ]
        connection.executemany(
            "INSERT INTO flow_archive VALUES (?, ?, ?, ?)",
            [
                (flow["flow_id"], flow["timestamp"], flow["label"], json.dumps(flow))
                for flow in flows
            ],
        )


def test_features_are_consistent_and_finite():
    features = features_from_flow(_flow("f", 10, 8000, 100, "benign"))
    assert features.shape == (4,)
    assert np.isfinite(features).all()


def test_train_score_archive_end_to_end(tmp_path):
    archive_path = tmp_path / "archive.db"
    model_path = tmp_path / "forest.joblib"
    _make_archive(archive_path)

    assert train_archive(str(archive_path), str(model_path), random_state=7) == 2
    model = joblib.load(model_path)
    assert isinstance(model, EarlyExitMVIForest)
    assert len(model.model.estimators_) == 51

    output = io.StringIO()
    assert score_archive(str(archive_path), str(model_path), output) == 3
    results = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [row["flow_id"] for row in results] == [
        "attack-1",
        "benign-1",
        "benign-2",
    ]
    assert all(0.0 <= row["s_score"] <= 1.0 for row in results)
    assert all(
        row["route"] in {"CLEAR", "SLOW_BRAIN", "FAST_TRACK"} for row in results
    )


def test_train_and_score_canonical_jsonl_with_bounded_sample(tmp_path):
    source = tmp_path / "ugr16.jsonl"
    model_path = tmp_path / "forest.joblib"
    flows = [
        {
            "flow_id": flow_id,
            "source_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "protocol": "tcp",
            "packet_count": packets,
            "byte_count": byte_count,
            "duration_ms": duration,
            "label": label,
        }
        for flow_id, packets, byte_count, duration, label in [
            ("normal-1", 10, 8000, 100, "background"),
            ("normal-2", 12, 9000, 110, "background"),
            ("normal-3", 9, 7000, 90, "background"),
            ("attack-1", 10000, 8000000, 5, "scan"),
        ]
    ]
    source.write_text(
        "".join(json.dumps(flow) + "\n" for flow in flows),
        encoding="utf-8",
    )

    trained_count = train_jsonl(
        str(source),
        str(model_path),
        random_state=7,
        normal_labels={"background"},
        max_training_rows=2,
    )
    assert trained_count == 2

    output = io.StringIO()
    assert score_jsonl(str(source), str(model_path), output) == 4
    results = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [row["flow_id"] for row in results] == [flow["flow_id"] for flow in flows]
    assert all(0.0 <= row["s_score"] <= 1.0 for row in results)
