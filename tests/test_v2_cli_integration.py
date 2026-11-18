"""Fast Brain CLI must honour the model's feature set (regression: CLI was hard-wired to V1)."""
import io
import json
import sqlite3

import joblib
import numpy as np
import pytest

from soc_agent import fast_brain_cli as cli
from soc_agent.features import V1_FEATURES, V2_FEATURES, extract_features
from soc_agent.fast_brain import EarlyExitMVIForest, features_from_flow
from tests.test_fast_brain_integration import _flow, _make_archive


def _jsonl(tmp_path, n=40):
    path = tmp_path / "flows.jsonl"
    rows = []
    for i in range(n):
        f = _flow(f"b{i}", 10 + i % 5, 8000 + 50 * i, 100 + i, "benign")
        f.update(src_port=50000 + i, dst_port=443, protocol="tcp")
        rows.append(f)
    attack = _flow("a0", 1, 40, 1, "attack")
    attack.update(src_port=80, dst_port=22, protocol="udp")
    rows.append(attack)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def test_default_is_v1_and_unchanged(tmp_path):
    src, model = _jsonl(tmp_path), tmp_path / "m.joblib"
    assert cli.main(["train", "--input", str(src), "--model", str(model)]) == 0
    forest = joblib.load(model)
    assert forest.feature_set == "v1" and forest.n_features == len(V1_FEATURES)


def test_train_v2_jsonl_records_feature_set(tmp_path):
    src, model = _jsonl(tmp_path), tmp_path / "m.joblib"
    assert cli.main(["train", "--input", str(src), "--model", str(model), "--feature-set", "v2"]) == 0
    forest = joblib.load(model)
    assert forest.feature_set == "v2" and forest.n_features == len(V2_FEATURES)


def test_score_uses_model_feature_set_not_v1(tmp_path):
    src, model, out = _jsonl(tmp_path), tmp_path / "m.joblib", tmp_path / "s.jsonl"
    cli.main(["train", "--input", str(src), "--model", str(model), "--feature-set", "v2"])
    assert cli.main(["score", "--input", str(src), "--model", str(model), "--output", str(out)]) == 0
    forest = joblib.load(model)
    rows = [json.loads(l) for l in out.read_text().splitlines()]
    flows = [json.loads(l) for l in src.read_text().splitlines()]
    for row, flow in zip(rows, flows):
        expected = forest.compute_s_score(extract_features(flow, "v2"))
        assert row["s_score"] == pytest.approx(expected)


def test_v1_extractor_cannot_score_a_v2_model(tmp_path):
    """Documents the original bug: a V2 model fed V1 vectors fails on width, not silently."""
    src, model = _jsonl(tmp_path), tmp_path / "m.joblib"
    cli.main(["train", "--input", str(src), "--model", str(model), "--feature-set", "v2"])
    forest = joblib.load(model)
    flow = json.loads(src.read_text().splitlines()[0])
    with pytest.raises(Exception):
        forest.compute_s_score(features_from_flow(flow))


def test_train_v2_from_go_archive_schema(tmp_path):
    archive, model, out = tmp_path / "a.db", tmp_path / "m.joblib", tmp_path / "s.jsonl"
    _make_archive(archive)
    with sqlite3.connect(archive) as c:  # make archived raw_json carry the V2 fields
        rows = c.execute("SELECT flow_id, raw_json FROM flow_archive").fetchall()
        for fid, raw in rows:
            d = json.loads(raw)
            d.setdefault("src_port", 51000)
            d.setdefault("dst_port", 443)
            d.setdefault("protocol", "tcp")
            c.execute("UPDATE flow_archive SET raw_json=? WHERE flow_id=?", (json.dumps(d), fid))
    assert cli.main(["train", "--archive", str(archive), "--model", str(model), "--feature-set", "v2"]) == 0
    assert cli.main(["score", "--archive", str(archive), "--model", str(model), "--output", str(out)]) == 0
    assert joblib.load(model).feature_set == "v2"
    assert len(out.read_text().splitlines()) == 3


def test_v2_training_rejects_flows_missing_required_fields(tmp_path):
    src = tmp_path / "f.jsonl"
    rows = []
    for i in range(4):
        f = _flow(f"b{i}", 10, 8000, 100, "benign")
        f.pop("src_port", None)
        f.pop("dst_port", None)
        f.pop("protocol", None)
        rows.append(f)
    src.write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(ValueError, match="src_port|dst_port|protocol"):
        cli.train_jsonl(str(src), str(tmp_path / "m.joblib"), 7, {"benign"}, 100, "v2")


def test_legacy_pickle_without_feature_set_is_v1():
    forest = EarlyExitMVIForest(random_state=1)
    forest.__dict__.pop("feature_set", None)
    assert forest.feature_set == "v1"
