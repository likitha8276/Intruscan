import hashlib
import json
import os

import pytest

from soc_agent import thresholds as th
from soc_agent.fast_brain import EarlyExitMVIForest

route = EarlyExitMVIForest.route_flow
SHA_A = "a" * 64
SHA_B = "b" * 64


def _approved(sha=SHA_A, lower=0.3, upper=0.7, **extra):
    return {
        "schema_version": th.SCHEMA_VERSION,
        "status": th.STATUS_APPROVED,
        "lower_threshold": lower,
        "upper_threshold": upper,
        "model_sha256": sha,
        **extra,
    }


# --- routing boundaries ------------------------------------------------------


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, "CLEAR"),
        (0.399999, "CLEAR"),
        (0.40, "SLOW_BRAIN"),
        (0.60, "SLOW_BRAIN"),
        (0.85, "SLOW_BRAIN"),
        (0.850001, "FAST_TRACK"),
        (1.0, "FAST_TRACK"),
    ],
)
def test_default_routing_is_backward_compatible(score, expected):
    assert route(score) == expected
    assert route(score, 0.40, 0.85) == expected


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.29, "CLEAR"),  # below lower
        (0.30, "SLOW_BRAIN"),  # exactly lower
        (0.50, "SLOW_BRAIN"),  # between
        (0.70, "SLOW_BRAIN"),  # exactly upper
        (0.71, "FAST_TRACK"),  # above upper
    ],
)
def test_custom_threshold_boundaries(score, expected):
    assert route(score, 0.30, 0.70) == expected


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.1, 1.1])
def test_score_validation_is_preserved(bad):
    with pytest.raises(ValueError, match="s_score must be a finite value"):
        route(bad)
    with pytest.raises(ValueError, match="s_score must be a finite value"):
        route(bad, 0.3, 0.7)


@pytest.mark.parametrize(
    "lower, upper, match",
    [
        (float("nan"), 0.8, "finite"),
        (0.2, float("inf"), "finite"),
        (float("-inf"), 0.8, "finite"),
        (-0.1, 0.5, "between 0 and 1"),
        (0.5, 1.1, "between 0 and 1"),
        (0.5, 0.5, "strictly smaller"),
        (0.7, 0.3, "strictly smaller"),
        ("0.2", 0.5, "must be a number"),
        (True, 0.5, "must be a number"),
        (None, 0.5, "must be a number"),
    ],
)
def test_invalid_threshold_pairs_are_rejected(lower, upper, match):
    with pytest.raises(th.ThresholdConfigError, match=match):
        th.validate_thresholds(lower, upper)
    with pytest.raises(ValueError, match=match):
        route(0.5, lower, upper)


def test_valid_pair_accepts_boundaries_of_unit_interval():
    assert th.validate_thresholds(0, 1) == (0.0, 1.0)


# --- fingerprint -------------------------------------------------------------


def test_fingerprint_is_sha256_of_file_bytes_and_content_sensitive(tmp_path):
    first = tmp_path / "a.bin"
    second = tmp_path / "b.bin"
    first.write_bytes(b"model-bytes")
    second.write_bytes(b"model-bytes!")
    assert th.model_fingerprint(first) == hashlib.sha256(b"model-bytes").hexdigest()
    assert th.model_fingerprint(first) == th.model_fingerprint(first)
    assert th.model_fingerprint(first) != th.model_fingerprint(second)


# --- configuration validation ------------------------------------------------


def test_valid_approved_config_loads():
    config = th.validate_config(
        _approved(), expect_status=th.STATUS_APPROVED, model_sha256=SHA_A
    )
    assert (config.lower, config.upper) == (0.3, 0.7)


def test_model_fingerprint_mismatch_is_rejected():
    with pytest.raises(th.ThresholdConfigError, match="different model"):
        th.validate_config(
            _approved(SHA_A), expect_status=th.STATUS_APPROVED, model_sha256=SHA_B
        )


@pytest.mark.parametrize("version", [None, 0, 2, "1", True])
def test_unsupported_schema_version_is_rejected(version):
    data = _approved()
    data["schema_version"] = version
    with pytest.raises(th.ThresholdConfigError, match="unsupported schema_version"):
        th.validate_config(data, expect_status=th.STATUS_APPROVED)


def test_candidate_cannot_be_used_as_approved():
    data = _approved()
    data["status"] = th.STATUS_CANDIDATE
    with pytest.raises(th.ThresholdConfigError, match="must be approved"):
        th.validate_config(data, expect_status=th.STATUS_APPROVED, model_sha256=SHA_A)


@pytest.mark.parametrize("sha", [None, "", "abc", "A" * 64, 123])
def test_bad_model_sha_is_rejected(sha):
    data = _approved()
    data["model_sha256"] = sha
    with pytest.raises(th.ThresholdConfigError, match="model_sha256"):
        th.validate_config(data, expect_status=th.STATUS_APPROVED)


def test_config_with_null_thresholds_is_rejected():
    with pytest.raises(th.ThresholdConfigError, match="must be a number"):
        th.validate_config(
            _approved(lower=None, upper=None), expect_status=th.STATUS_APPROVED
        )


def test_read_json_object_reports_syntax_errors_and_non_objects(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{\n  "lower_threshold": 0.3,\n  oops\n}', encoding="utf-8")
    with pytest.raises(th.ThresholdConfigError, match="line 3"):
        th.read_json_object(bad)
    listy = tmp_path / "list.json"
    listy.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(th.ThresholdConfigError, match="JSON object"):
        th.read_json_object(listy)
    with pytest.raises(FileNotFoundError):
        th.read_json_object(tmp_path / "missing.json")


# --- resolution: fallback only when missing ----------------------------------


@pytest.fixture
def model_file(tmp_path):
    path = tmp_path / "model.joblib"
    path.write_bytes(b"pretend-model")
    return path


def test_missing_config_falls_back_to_defaults_and_says_so(tmp_path, model_file):
    resolved = th.resolve_routing_thresholds(tmp_path / "absent.json", model_file)
    assert (resolved.lower, resolved.upper) == (0.40, 0.85)
    assert resolved.source == "fallback"
    assert "using built-in defaults" in resolved.describe()


def test_default_path_is_used_when_none_given(tmp_path, model_file):
    th.atomic_write_json(
        th.DEFAULT_APPROVED_PATH,
        _approved(th.model_fingerprint(model_file), 0.2, 0.9),
        overwrite=False,
    )
    resolved = th.resolve_routing_thresholds(None, model_file)
    assert (resolved.lower, resolved.upper, resolved.source) == (0.2, 0.9, "approved")


def test_valid_config_for_this_model_is_used(tmp_path, model_file):
    path = tmp_path / "t.json"
    path.write_text(
        json.dumps(_approved(th.model_fingerprint(model_file), 0.35, 0.8)),
        encoding="utf-8",
    )
    resolved = th.resolve_routing_thresholds(path, model_file)
    assert (resolved.lower, resolved.upper, resolved.source) == (0.35, 0.8, "approved")


@pytest.mark.parametrize(
    "text, match",
    [
        ("{not json", "not valid JSON"),
        ('{"schema_version": 1, "status": "approved", "lower_threshold": NaN, '
         '"upper_threshold": 0.8, "model_sha256": "%s"}' % SHA_A, "finite"),
        ('{"schema_version": 1, "status": "approved", "lower_threshold": 0.9, '
         '"upper_threshold": 0.8, "model_sha256": "%s"}' % SHA_A, "strictly smaller"),
        ('{"schema_version": 1, "status": "approved", "lower_threshold": 0.8, '
         '"upper_threshold": 0.8, "model_sha256": "%s"}' % SHA_A, "strictly smaller"),
        ('{"schema_version": 9, "status": "approved"}', "unsupported schema_version"),
    ],
)
def test_invalid_existing_config_is_an_error_not_a_fallback(tmp_path, model_file, text, match):
    path = tmp_path / "t.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(th.ThresholdConfigError, match=match):
        th.resolve_routing_thresholds(path, model_file)


def test_config_for_another_model_is_an_error(tmp_path, model_file):
    path = tmp_path / "t.json"
    path.write_text(json.dumps(_approved(SHA_B)), encoding="utf-8")
    with pytest.raises(th.ThresholdConfigError, match="different model"):
        th.resolve_routing_thresholds(path, model_file)


# --- atomic writes -----------------------------------------------------------


def test_atomic_write_refuses_to_overwrite_and_leaves_no_temp_files(tmp_path):
    target = tmp_path / "out" / "thresholds.json"
    th.atomic_write_json(target, {"a": 1}, overwrite=False)
    with pytest.raises(th.ThresholdConfigError, match="already exists"):
        th.atomic_write_json(target, {"a": 2}, overwrite=False)
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}

    th.atomic_write_json(target, {"a": 3}, overwrite=True)
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 3}
    assert os.listdir(target.parent) == ["thresholds.json"]


def test_atomic_write_rejects_non_finite_values_without_creating_a_file(tmp_path):
    target = tmp_path / "t.json"
    with pytest.raises(ValueError):
        th.atomic_write_json(target, {"x": float("nan")}, overwrite=False)
    assert os.listdir(tmp_path) == []
