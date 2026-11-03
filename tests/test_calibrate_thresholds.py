import json

import pytest

from tools.calibrate_thresholds import load_scores, main


def _write_scored_flows(path, labels_and_scores):
    path.write_text(
        "".join(
            json.dumps({"label": label, "s_score": score}) + "\n"
            for label, score in labels_and_scores
        ),
        encoding="utf-8",
    )


def test_load_scores_separates_exact_benign_label(tmp_path):
    path = tmp_path / "scored.jsonl"
    _write_scored_flows(
        path,
        [
            ("background", 0.1),
            ("background", 0.2),
            ("scan", 0.8),
            ("anomaly", 0.9),
        ],
    )

    benign, anomalous = load_scores(path, "background")

    assert benign.tolist() == [0.1, 0.2]
    assert anomalous.tolist() == [0.8, 0.9]


def test_main_prints_thresholds_and_writes_histogram(tmp_path, capsys):
    source = tmp_path / "scored.jsonl"
    plot = tmp_path / "calibration.png"
    rows = [("background", i / 100) for i in range(1, 101)]
    rows += [("scan", 0.7 + i / 1000) for i in range(1, 101)]
    _write_scored_flows(source, rows)

    assert main(["--input", str(source), "--plot", str(plot)]) == 0

    output = capsys.readouterr().out
    assert "benign 90th percentile" in output
    assert "anomalous  5th percentile" in output
    assert "CLEAR/SLOW_BRAIN lower threshold" in output
    assert plot.is_file()
    assert plot.stat().st_size > 0


def test_main_reports_missing_default_benign_label(tmp_path, capsys):
    source = tmp_path / "scored.jsonl"
    _write_scored_flows(source, [("benign", 0.1), ("attack", 0.9)])

    assert main(["--input", str(source), "--plot", str(tmp_path / "plot.png")]) == 1

    error = capsys.readouterr().err
    assert "no rows have benign label 'background'" in error


def test_load_scores_rejects_non_finite_scores(tmp_path):
    path = tmp_path / "scored.jsonl"
    _write_scored_flows(
        path,
        [("background", 0.1), ("scan", float("inf"))],
    )

    with pytest.raises(ValueError, match="infinite s_score"):
        load_scores(path, "background")
