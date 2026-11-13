import hashlib
import io
import json

import joblib
import numpy as np
import pytest

from soc_agent import thresholds as th
from soc_agent.fast_brain import EarlyExitMVIForest, features_from_flow
from soc_agent.fast_brain_cli import score_jsonl
from tools.calibrate_thresholds import (
    CalibrationError,
    InfeasibleThresholdsError,
    load_model,
    load_scores,
    lower_for_benign_escalation_rate,
    main,
    overlap_report,
    read_flow_records,
    route_metrics,
    score_flows,
    select_thresholds,
    upper_for_fast_track_recall,
)


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


def test_legacy_mode_rejects_non_numeric_scores_and_writes_no_candidate(tmp_path, capsys):
    path = tmp_path / "scored.jsonl"
    path.write_text(
        '{"label": "background", "s_score": "abc"}\n'
        '{"label": "scan", "s_score": 0.9}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="non-numeric"):
        load_scores(path, "background")

    rows = [("benign", i / 100) for i in range(1, 51)] + [("scan", 0.9)] * 5
    _write_scored_flows(path, rows)
    assert main(["--input", str(path), "--benign-label", "benign",
                 "--plot", str(tmp_path / "p.png")]) == 0
    assert "no candidate file was written" in capsys.readouterr().out
    assert not th.DEFAULT_APPROVED_PATH.exists()


# =============================================================================
# Model-bound workflow
# =============================================================================


def _calibrate(wf, tmp_path, *extra, name="candidate.json", data=None):
    out = tmp_path / name
    code = main(
        [
            "calibrate",
            "--model", str(wf.model),
            "--input", str(data or wf.calibration),
            "--benign-label", "benign",
            "--min-benign", "20",
            "--min-attack", "10",
            "--candidate-output", str(out),
            "--plot", str(tmp_path / "plot.png"),
            *extra,
        ]
    )
    return code, out


EXPLICIT = ("--lower", "0.55", "--upper", "0.65")


def _evaluate(wf, candidate, *, test=None, cal=None, model=None, extra=()):
    return main(
        [
            "evaluate",
            "--candidate", str(candidate),
            "--model", str(model or wf.model),
            "--calibration-input", str(cal or wf.calibration),
            "--input", str(test or wf.test),
            "--min-benign", "20",
            "--min-attack", "10",
            *extra,
        ]
    )


def _approve(wf, candidate, output, *extra, model=None):
    return main(
        [
            "approve",
            "--candidate", str(candidate),
            "--model", str(model or wf.model),
            "--output", str(output),
            "--approved-by", "tester",
            *extra,
        ]
    )


def _json(path):
    return json.loads(path.read_text(encoding="utf-8"))


# --- model loading ------------------------------------------------------------


def test_load_model_returns_the_exact_saved_model(workflow_files):
    loaded = load_model(workflow_files.model)
    reference = joblib.load(workflow_files.model)

    assert isinstance(loaded, EarlyExitMVIForest)
    assert len(loaded.model.estimators_) == 51
    records = read_flow_records(workflow_files.calibration, "benign")
    scored = score_flows(loaded, workflow_files.calibration, "benign")
    expected = [
        reference.compute_s_score(features_from_flow(record.flow)) for record in records
    ]
    assert scored.scores.tolist() == expected


def test_load_model_rejects_wrong_objects_and_missing_files(tmp_path):
    joblib.dump({"not": "a model"}, tmp_path / "dict.joblib")
    (tmp_path / "junk.joblib").write_bytes(b"junk")
    with pytest.raises(CalibrationError, match="EarlyExitMVIForest"):
        load_model(tmp_path / "dict.joblib")
    with pytest.raises(CalibrationError, match="could not load"):
        load_model(tmp_path / "junk.joblib")
    with pytest.raises(CalibrationError, match="not found"):
        load_model(tmp_path / "missing.joblib")


def test_calibration_does_not_retrain_or_rebuild_the_model(
    workflow_files, tmp_path, monkeypatch
):
    before = workflow_files.model.read_bytes()

    def boom(*args, **kwargs):
        raise AssertionError("calibration rebuilt or refit the model")

    monkeypatch.setattr(EarlyExitMVIForest, "fit", boom)
    monkeypatch.setattr(EarlyExitMVIForest, "__init__", boom)

    code, out = _calibrate(workflow_files, tmp_path, *EXPLICIT)

    assert code == 0
    assert workflow_files.model.read_bytes() == before
    assert _json(out)["model_sha256"] == hashlib.sha256(before).hexdigest()


# --- candidate generation (never active) ---------------------------------------


def test_calibrate_writes_a_candidate_that_is_not_active(workflow_files, tmp_path):
    code, out = _calibrate(workflow_files, tmp_path, *EXPLICIT)
    candidate = _json(out)

    assert code == 0
    assert candidate["status"] == "candidate"
    assert candidate["schema_version"] == th.SCHEMA_VERSION
    assert (candidate["lower_threshold"], candidate["upper_threshold"]) == (0.55, 0.65)
    assert candidate["benign_label"] == "benign"
    assert candidate["calibration"]["n_benign"] == 60
    assert candidate["calibration"]["n_attack"] == 30
    assert candidate["calibration"]["input_sha256"] == th.file_sha256(
        workflow_files.calibration
    )
    assert candidate["selection"]["lower"]["method"] == "explicit_operating_point"
    assert candidate["evaluation"] is None
    assert candidate["overlap"]["ranges_overlap"] is True
    assert candidate["created_at"]
    assert (tmp_path / "plot.png").is_file()
    # Nothing became active, and scoring refuses the candidate.
    assert not th.DEFAULT_APPROVED_PATH.exists()
    with pytest.raises(th.ThresholdConfigError, match="must be approved"):
        th.resolve_routing_thresholds(out, workflow_files.model)


def test_constraint_options_select_thresholds_from_calibration_data(
    workflow_files, tmp_path
):
    code, out = _calibrate(
        workflow_files,
        tmp_path,
        "--max-benign-escalation-rate", "0.2",
        "--min-fast-track-recall", "0.01",
    )
    selection = _json(out)["selection"]

    assert code == 0
    assert selection["lower"]["method"] == "max_benign_escalation_rate"
    assert selection["upper"]["method"] == "min_fast_track_recall"
    assert _json(out)["calibration_metrics"]["escalation"]["false_positive_rate"] <= 0.2


def test_overlapping_distributions_yield_no_default_candidate(
    workflow_files, tmp_path, capsys
):
    code, out = _calibrate(workflow_files, tmp_path)  # percentile baseline

    err = capsys.readouterr().err
    assert code == 2
    assert not out.exists()
    assert "overlap" in err.lower()
    assert "No reliable threshold pair" in err


@pytest.mark.parametrize(
    "lower, upper",
    [("0.7", "0.6"), ("0.6", "0.6"), ("-0.1", "0.6"), ("0.5", "1.5")],
)
def test_invalid_explicit_pairs_are_refused(workflow_files, tmp_path, lower, upper):
    code, out = _calibrate(workflow_files, tmp_path, "--lower", lower, "--upper", upper)
    assert code == 2
    assert not out.exists()


def test_lower_and_upper_must_come_together_and_not_mix_with_constraints(
    workflow_files, tmp_path
):
    with pytest.raises(SystemExit):
        _calibrate(workflow_files, tmp_path, "--lower", "0.5")
    with pytest.raises(SystemExit):
        _calibrate(workflow_files, tmp_path, *EXPLICIT, "--max-benign-escalation-rate", "0.1")


def test_benign_label_is_required_for_the_new_workflow(workflow_files, tmp_path):
    with pytest.raises(SystemExit):
        main(["calibrate", "--model", str(workflow_files.model),
              "--input", str(workflow_files.calibration)])


def test_existing_candidate_is_not_silently_overwritten(workflow_files, tmp_path):
    code, out = _calibrate(workflow_files, tmp_path, *EXPLICIT)
    assert code == 0
    original = out.read_text(encoding="utf-8")

    assert _calibrate(workflow_files, tmp_path, "--lower", "0.5", "--upper", "0.7")[0] == 1
    assert out.read_text(encoding="utf-8") == original
    assert _calibrate(
        workflow_files, tmp_path, "--lower", "0.5", "--upper", "0.7",
        "--overwrite-candidate",
    )[0] == 0
    assert _json(out)["lower_threshold"] == 0.5


def test_candidate_cannot_be_written_to_the_approved_location(workflow_files, tmp_path):
    th.DEFAULT_APPROVED_PATH.parent.mkdir(parents=True)
    code = main(
        ["calibrate", "--model", str(workflow_files.model),
         "--input", str(workflow_files.calibration), "--benign-label", "benign",
         "--min-benign", "20", "--min-attack", "10", *EXPLICIT,
         "--candidate-output", str(th.DEFAULT_APPROVED_PATH),
         "--plot", str(tmp_path / "p.png")]
    )
    assert code == 1
    assert not th.DEFAULT_APPROVED_PATH.exists()


# --- input validation -----------------------------------------------------------


def _bad_file(tmp_path, lines):
    path = tmp_path / "bad.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


_GOOD = '{"flow_id": "x", "packets": 10, "bytes": 8000, "duration_ms": 100, "label": "benign"}'


@pytest.mark.parametrize(
    "lines, match",
    [
        ([_GOOD, _GOOD, "{not json"], r"line 3.*invalid JSON"),
        ([_GOOD, "[1, 2]"], r"line 2.*JSON object"),
        ([_GOOD, '{"packets": 1, "bytes": 1}'], r"line 2.*missing required field 'label'"),
        ([_GOOD, '{"label": 5, "packets": 1, "bytes": 1}'], r"line 2.*label must be a non-empty string"),
        ([_GOOD, '{"label": "  ", "packets": 1, "bytes": 1}'], r"line 2.*label must be a non-empty string"),
        ([_GOOD, '{"label": "Benign", "packets": 1, "bytes": 1}'], r"line 2.*only by case"),
    ],
)
def test_read_flow_records_reports_line_numbers(tmp_path, lines, match):
    with pytest.raises(CalibrationError, match=match):
        read_flow_records(_bad_file(tmp_path, lines), "benign")


def test_attack_label_allow_list_rejects_unknown_labels(tmp_path):
    path = _bad_file(tmp_path, [_GOOD, _GOOD.replace('"benign"', '"scna"')])
    with pytest.raises(CalibrationError, match=r"line 2.*scna"):
        read_flow_records(path, "benign", {"scan"})
    assert len(read_flow_records(path, "benign")) == 2


@pytest.mark.parametrize(
    "bad_line, match",
    [
        ('{"label": "benign", "flow_id": "m"}', r"line 2.*cannot score flow"),
        ('{"label": "benign", "packets": "abc", "bytes": 5, "duration_ms": 1}', r"line 2.*cannot score flow"),
        ('{"label": "benign", "packets": 10, "bytes": Infinity, "duration_ms": 1}', r"line 2.*finite"),
        ('{"label": "benign", "packets": 10, "bytes": NaN, "duration_ms": 1}', r"line 2.*finite"),
        ('{"label": "benign", "packets": -1, "bytes": 5, "duration_ms": 1}', r"line 2.*non-negative"),
    ],
)
def test_unscorable_flows_are_reported_with_line_numbers(workflow_files, tmp_path, bad_line, match):
    path = _bad_file(tmp_path, [_GOOD, bad_line])
    with pytest.raises(CalibrationError, match=match):
        score_flows(load_model(workflow_files.model), path, "benign")


class _FixedScoreModel:
    def __init__(self, value):
        self.value = value

    def compute_s_score(self, _features):
        return self.value


@pytest.mark.parametrize("value", [1.5, -0.2, float("nan"), float("inf")])
def test_scores_outside_unit_interval_or_non_finite_are_rejected(tmp_path, value):
    path = _bad_file(tmp_path, [_GOOD])
    with pytest.raises(CalibrationError, match="invalid s_score"):
        score_flows(_FixedScoreModel(value), path, "benign")


def test_calibrate_cli_reports_validation_errors_with_exit_code_1(
    workflow_files, tmp_path, capsys
):
    path = _bad_file(tmp_path, [_GOOD, "{broken"])
    code, out = _calibrate(workflow_files, tmp_path, *EXPLICIT, data=path)
    assert code == 1
    assert not out.exists()
    assert "line 2" in capsys.readouterr().err


def test_missing_benign_or_attack_or_too_few_samples(workflow_files, tmp_path, flow_factory, jsonl_writer, capsys):
    only_attack = jsonl_writer(tmp_path / "a.jsonl", flow_factory("c", 0, 30, 1))
    only_benign = jsonl_writer(tmp_path / "b.jsonl", flow_factory("c", 60, 0, 1))
    small = jsonl_writer(tmp_path / "s.jsonl", flow_factory("c", 60, 30, 1))

    assert _calibrate(workflow_files, tmp_path, *EXPLICIT, data=only_attack)[0] == 1
    assert "no rows have benign label 'benign'" in capsys.readouterr().err
    assert _calibrate(workflow_files, tmp_path, *EXPLICIT, data=only_benign)[0] == 1
    assert "no attack rows" in capsys.readouterr().err
    assert _calibrate(workflow_files, tmp_path, *EXPLICIT, "--min-benign", "100", data=small)[0] == 1
    assert "only 60 benign samples; at least 100 required" in capsys.readouterr().err
    assert _calibrate(workflow_files, tmp_path, *EXPLICIT, "--min-attack", "50", data=small)[0] == 1
    assert "only 30 attack samples; at least 50 required" in capsys.readouterr().err


# --- selection and metrics (pure functions) -------------------------------------

_BENIGN = np.linspace(0.30, 0.50, 200)
_ATTACK = np.linspace(0.70, 0.95, 40)


def test_percentile_baseline_on_cleanly_separated_scores():
    lower, upper, selection = select_thresholds(_BENIGN, _ATTACK)

    assert lower == pytest.approx(np.quantile(_BENIGN, 0.95))
    assert upper == pytest.approx(np.quantile(_ATTACK, 0.05))
    assert lower < upper
    assert selection["lower"]["method"] == "benign_percentile"
    assert selection["upper"]["method"] == "attack_percentile"
    assert overlap_report(_BENIGN, _ATTACK)["ranges_overlap"] is False


def test_overlap_report_flags_overlapping_distributions():
    benign = np.linspace(0.3, 0.9, 100)
    attack = np.linspace(0.5, 0.95, 30)
    report = overlap_report(benign, attack)

    assert report["ranges_overlap"] is True
    assert report["percentiles_overlap"] is True
    assert report["requires_acknowledgement"] is True


def test_benign_escalation_rate_constraint_picks_the_smallest_qualifying_lower():
    lower = lower_for_benign_escalation_rate(_BENIGN, 0.10)
    values = np.unique(_BENIGN)
    previous = values[np.searchsorted(values, lower) - 1]

    assert np.mean(_BENIGN >= lower) <= 0.10
    assert np.mean(_BENIGN >= previous) > 0.10
    zero = lower_for_benign_escalation_rate(_BENIGN, 0.0)
    assert zero > _BENIGN.max() and np.mean(_BENIGN >= zero) == 0.0


def test_fast_track_recall_constraint_picks_the_largest_qualifying_upper():
    upper = upper_for_fast_track_recall(_ATTACK, 0.90)
    values = np.unique(_ATTACK)
    following = values[np.searchsorted(values, upper) + 1]

    assert np.mean(_ATTACK > upper) >= 0.90
    assert np.mean(_ATTACK > following) < 0.90
    full = upper_for_fast_track_recall(_ATTACK, 1.0)
    assert full < _ATTACK.min() and np.mean(_ATTACK > full) == 1.0


def test_infeasible_constraints_raise_instead_of_choosing_silently():
    benign = np.linspace(0.3, 0.9, 100)
    attack = np.linspace(0.3, 0.6, 30)
    with pytest.raises(InfeasibleThresholdsError, match="escalation recall"):
        select_thresholds(
            benign, attack, max_benign_escalation_rate=0.05, min_escalation_recall=0.9
        )
    with pytest.raises(InfeasibleThresholdsError, match="FAST_TRACK"):
        select_thresholds(
            np.linspace(0.3, 0.9, 100), np.linspace(0.3, 0.9, 30),
            min_fast_track_recall=0.9, max_benign_fast_track_rate=0.05,
        )


def test_route_metrics_separates_escalation_from_fast_track():
    scores = np.array([0.10, 0.40, 0.85, 0.90, 0.20, 0.40, 0.60, 0.95])
    is_attack = np.array([False] * 4 + [True] * 4)

    metrics = route_metrics(scores, is_attack, 0.40, 0.85)
    esc, ft, dist = metrics["escalation"], metrics["fast_track"], metrics["routing_distribution"]

    # Boundaries: 0.40 (== lower) and 0.85 (== upper) both route to SLOW_BRAIN.
    assert (esc["tp"], esc["fp"], esc["tn"], esc["fn"]) == (3, 3, 1, 1)
    assert esc["precision"] == pytest.approx(0.5)
    assert esc["escalation_recall"] == pytest.approx(0.75)
    assert esc["specificity"] == pytest.approx(0.25)
    assert esc["false_positive_rate"] == pytest.approx(0.75)
    assert esc["f1"] == pytest.approx(0.6)
    assert ft["fast_track_recall"] == pytest.approx(0.25)
    assert ft["fast_track_precision"] == pytest.approx(0.5)
    assert ft["benign_fast_track_rate"] == pytest.approx(0.25)
    assert dist["all"]["percent"] == {"CLEAR": 25.0, "SLOW_BRAIN": 50.0, "FAST_TRACK": 25.0}
    assert dist["benign"]["counts"] == {"CLEAR": 1, "SLOW_BRAIN": 2, "FAST_TRACK": 1}
    assert "recall" not in esc  # only the explicit escalation_recall exists
    assert "not a confirmed attack" in metrics["prediction_rule"]


def test_escalation_recall_and_fast_track_recall_can_differ_completely():
    metrics = route_metrics(np.array([0.5, 0.6]), np.array([True, True]), 0.4, 0.8)

    assert metrics["escalation"]["escalation_recall"] == 1.0
    assert metrics["fast_track"]["fast_track_recall"] == 0.0


def test_route_metrics_handles_zero_denominators():
    metrics = route_metrics(np.array([0.1, 0.2]), np.array([False, False]), 0.4, 0.8)
    esc, ft = metrics["escalation"], metrics["fast_track"]

    assert esc["precision"] is None and esc["f1"] is None
    assert esc["escalation_recall"] is None
    assert esc["specificity"] == 1.0 and esc["false_positive_rate"] == 0.0
    assert ft["fast_track_recall"] is None and ft["fast_track_precision"] is None


# --- evaluation, split integrity, approval --------------------------------------


def _candidate(wf, tmp_path, *extra, name="candidate.json"):
    code, out = _calibrate(wf, tmp_path, *(extra or EXPLICIT), name=name)
    assert code == 0
    return out


def test_evaluate_records_independent_metrics_without_changing_thresholds(
    workflow_files, tmp_path, capsys
):
    out = _candidate(workflow_files, tmp_path)
    before = _json(out)

    assert _evaluate(workflow_files, out) == 0
    after = _json(out)

    assert (after["lower_threshold"], after["upper_threshold"]) == (
        before["lower_threshold"], before["upper_threshold"],
    )
    assert after["status"] == "candidate"
    evaluation = after["evaluation"]
    assert evaluation["metrics"]["n"] == 90
    assert evaluation["test_input_sha256"] == th.file_sha256(workflow_files.test)
    assert evaluation["flow_id_check"]["status"] == "passed"
    assert evaluation["thresholds_evaluated"] == {"lower": 0.55, "upper": 0.65}
    assert "escalation_recall" in evaluation["metrics"]["escalation"]
    assert "fast_track_recall" in evaluation["metrics"]["fast_track"]
    assert after["evaluation_runs"] == 1
    assert "Independent test-set metrics" in capsys.readouterr().out

    assert _evaluate(workflow_files, out) == 0
    assert _json(out)["evaluation_runs"] == 2  # repeated test peeking stays visible


def test_evaluate_refuses_identical_overlapping_or_wrong_splits(
    workflow_files, tmp_path, flow_factory, jsonl_writer, capsys
):
    out = _candidate(workflow_files, tmp_path)

    assert _evaluate(workflow_files, out, test=workflow_files.calibration) == 1
    assert "identical to the calibration file" in capsys.readouterr().err

    leaky_rows = flow_factory("test", 60, 30, 3, attack_like=5) + flow_factory("cal", 1, 0, 2)
    leaky = jsonl_writer(tmp_path / "leaky.jsonl", leaky_rows)
    assert _evaluate(workflow_files, out, test=leaky) == 1
    err = capsys.readouterr().err
    assert "data leakage" in err and "cal-b0" in err
    assert _json(out)["evaluation"] is None  # nothing recorded on failure

    assert _evaluate(workflow_files, out, cal=workflow_files.test) == 1
    assert "SHA-256 mismatch" in capsys.readouterr().err


def test_evaluate_notes_when_flow_ids_are_unavailable(
    workflow_files, tmp_path, flow_factory, jsonl_writer
):
    out = _candidate(workflow_files, tmp_path)
    rows = flow_factory("test", 60, 30, 3, attack_like=5)
    for row in rows:
        del row["flow_id"]
    anonymous = jsonl_writer(tmp_path / "anon.jsonl", rows)

    assert _evaluate(workflow_files, out, test=anonymous) == 0
    assert _json(out)["evaluation"]["flow_id_check"]["status"] == "unavailable"


def test_evaluate_requires_enough_test_samples(workflow_files, tmp_path, capsys):
    out = _candidate(workflow_files, tmp_path)
    assert _evaluate(workflow_files, out, extra=("--min-benign", "1000")) == 1
    assert "test data: only 60 benign samples" in capsys.readouterr().err


def test_model_fingerprint_mismatch_is_rejected_by_evaluate_and_approve(
    workflow_files, tmp_path, capsys
):
    out = _candidate(workflow_files, tmp_path)
    approved = tmp_path / "approved.json"

    assert _evaluate(workflow_files, out, model=workflow_files.other_model) == 1
    assert "different model" in capsys.readouterr().err
    assert _approve(workflow_files, out, approved, model=workflow_files.other_model) == 1
    assert "different model" in capsys.readouterr().err
    assert not approved.exists()


def test_approval_requires_an_evaluation(workflow_files, tmp_path, capsys):
    out = _candidate(workflow_files, tmp_path)
    approved = tmp_path / "approved.json"

    assert _approve(workflow_files, out, approved, "--acknowledge-overlap") == 1
    assert "run 'evaluate' first" in capsys.readouterr().err
    assert not approved.exists()


def test_approval_rejects_thresholds_edited_after_evaluation(workflow_files, tmp_path, capsys):
    out = _candidate(workflow_files, tmp_path)
    assert _evaluate(workflow_files, out) == 0
    edited = _json(out)
    edited["lower_threshold"] = 0.56
    out.write_text(json.dumps(edited), encoding="utf-8")
    approved = tmp_path / "approved.json"

    assert _approve(workflow_files, out, approved, "--acknowledge-overlap") == 1
    assert "different thresholds" in capsys.readouterr().err
    assert not approved.exists()


def test_full_workflow_requires_explicit_approval_and_never_overwrites(
    workflow_files, tmp_path, capsys
):
    out = _candidate(workflow_files, tmp_path)
    assert _evaluate(workflow_files, out) == 0
    approved = tmp_path / "approved.json"

    # Overlapping calibration ranges need an explicit acknowledgement.
    assert _approve(workflow_files, out, approved) == 1
    assert "--acknowledge-overlap" in capsys.readouterr().err
    assert not approved.exists()
    assert not th.DEFAULT_APPROVED_PATH.exists()

    assert _approve(workflow_files, out, approved, "--acknowledge-overlap") == 0
    document = _json(approved)
    assert document["status"] == "approved"
    assert document["approved_by"] == "tester"
    assert document["overlap_acknowledged"] is True
    assert document["evaluation"]["metrics"]["n"] == 90
    config = th.load_approved_thresholds(approved, th.model_fingerprint(workflow_files.model))
    assert (config.lower, config.upper) == (0.55, 0.65)
    assert _json(out)["status"] == "candidate"  # the candidate itself is untouched

    # No accidental overwrite of an existing approved configuration.
    original = approved.read_text(encoding="utf-8")
    assert _approve(workflow_files, out, approved, "--acknowledge-overlap") == 1
    assert "already exists" in capsys.readouterr().err
    assert approved.read_text(encoding="utf-8") == original
    assert _approve(workflow_files, out, approved, "--acknowledge-overlap", "--replace") == 0

    # Fast Brain now routes with the approved thresholds for this exact model.
    output = io.StringIO()
    score_jsonl(str(workflow_files.test), str(workflow_files.model), output, str(approved))
    rows = [json.loads(line) for line in output.getvalue().splitlines()]
    assert all(
        row["route"] == EarlyExitMVIForest.route_flow(row["s_score"], 0.55, 0.65)
        for row in rows
    )


def test_approval_without_overlap_needs_no_acknowledgement(workflow_files, tmp_path):
    out = _candidate(workflow_files, tmp_path)
    assert _evaluate(workflow_files, out) == 0
    document = _json(out)
    document["overlap"]["requires_acknowledgement"] = False
    out.write_text(json.dumps(document), encoding="utf-8")

    assert _approve(workflow_files, out, tmp_path / "approved.json") == 0
