"""Shared, deterministic fixtures for Fast Brain threshold tests.

Nothing here touches real datasets, model artifacts or external services.
"""

import json
import random
from types import SimpleNamespace

import joblib
import numpy as np
import pytest

from soc_agent import thresholds as th
from soc_agent.fast_brain import EarlyExitMVIForest, features_from_flow


def make_flows(prefix, n_benign, n_attack, seed, benign_label="benign", attack_like=0):
    """Synthetic flows. The first ``attack_like`` attacks resemble benign traffic."""
    rng = random.Random(seed)
    rows = []
    for index in range(n_benign):
        packets = rng.randint(8, 14)
        rows.append(
            {
                "flow_id": f"{prefix}-b{index}",
                "packets": packets,
                "bytes": packets * rng.randint(700, 900),
                "duration_ms": rng.randint(90, 130),
                "label": benign_label,
            }
        )
    for index in range(n_attack):
        if index < attack_like:
            packets = rng.randint(8, 14)
            bytes_ = packets * rng.randint(700, 900)
            duration, label = rng.randint(90, 130), "scan"
        else:
            packets = rng.randint(5000, 20000)
            bytes_ = packets * rng.randint(700, 900)
            duration, label = rng.randint(1, 20), "flood"
        rows.append(
            {
                "flow_id": f"{prefix}-a{index}",
                "packets": packets,
                "bytes": bytes_,
                "duration_ms": duration,
                "label": label,
            }
        )
    return rows


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def train_model(path, seed=1, random_state=7, n=300):
    flows = make_flows("train", n, 0, seed=seed)
    forest = EarlyExitMVIForest(random_state=random_state).fit(
        np.vstack([features_from_flow(flow) for flow in flows])
    )
    joblib.dump(forest, path)
    return path


@pytest.fixture(autouse=True)
def _isolate_default_thresholds(monkeypatch, tmp_path):
    """Never let a real soc_agent/thresholds.json leak into tests."""
    monkeypatch.setattr(
        th, "DEFAULT_APPROVED_PATH", tmp_path / "no_default_dir" / "thresholds.json"
    )


@pytest.fixture(scope="session")
def workflow_files(tmp_path_factory):
    """One trained model plus disjoint calibration and test files (read-only)."""
    root = tmp_path_factory.mktemp("fastbrain_workflow")
    model = train_model(root / "model.joblib")
    other = train_model(root / "other_model.joblib", seed=5, random_state=11)
    # attack_like=5: five "attacks" look benign, so benign/attack score ranges
    # overlap by construction (independent of the exact model scores).
    calibration = write_jsonl(
        root / "calibration.jsonl", make_flows("cal", 60, 30, 2, attack_like=5)
    )
    test = write_jsonl(
        root / "test.jsonl", make_flows("test", 60, 30, 3, attack_like=5)
    )
    return SimpleNamespace(
        root=root, model=model, other_model=other, calibration=calibration, test=test
    )


@pytest.fixture
def flow_factory():
    return make_flows


@pytest.fixture
def jsonl_writer():
    return write_jsonl
