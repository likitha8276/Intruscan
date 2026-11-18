import json

from soc_agent.fast_track_check import (
    OUTCOME_CONFIRM,
    OUTCOME_REVIEW,
    apply_to_store,
    rule_check,
    source_stats,
)
from soc_agent.incidents import IncidentStore, fast_track_incident

UPPER = 0.635351


def _flow(i, src, route, score, dst="10.0.0.1"):
    return {
        "flow_id": f"f{i}", "timestamp": "2016-07-29T09:34:54Z", "src_ip": src,
        "dst_ip": dst, "dst_port": 80, "protocol": "tcp", "route": route, "s_score": score,
    }


def _write(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def test_corroborated_source_is_confirmed(tmp_path):
    rows = [_flow(i, "1.1.1.1", "FAST_TRACK", 0.70) for i in range(4)]
    path = tmp_path / "s.jsonl"
    _write(path, rows)
    result = rule_check(src="1.1.1.1", s_score=0.70, upper=UPPER, stats=source_stats(path)["1.1.1.1"])
    assert result["outcome"] == OUTCOME_CONFIRM
    assert result["gate_flags"] == []
    assert result["check_type"] == "rule_based_no_llm"


def test_isolated_mostly_clear_source_is_flagged_but_small_margin_is_not(tmp_path):
    rows = [_flow(0, "2.2.2.2", "FAST_TRACK", UPPER + 0.001)]
    rows += [_flow(i, "2.2.2.2", "CLEAR", 0.4) for i in range(1, 50)]
    path = tmp_path / "s.jsonl"
    _write(path, rows)
    result = rule_check(src="2.2.2.2", s_score=rows[0]["s_score"], upper=UPPER, stats=source_stats(path)["2.2.2.2"])
    assert result["outcome"] == OUTCOME_REVIEW
    text = " ".join(result["gate_flags"])
    assert "isolated_flow" in text and "source_mostly_clear" in text
    assert "marginal_score" not in text


def test_missing_inputs_never_confirm():
    result = rule_check(src="x", s_score=None, upper=None, stats=None)
    assert result["outcome"] == OUTCOME_REVIEW
    assert "score_unavailable" in result["gate_flags"]


def test_apply_to_store_keeps_priority_and_is_repeatable(tmp_path):
    rows = [_flow(i, "3.3.3.3", "FAST_TRACK", 0.7) for i in range(3)]
    scored = tmp_path / "s.jsonl"
    _write(scored, rows)
    store = IncidentStore(tmp_path / "i.db")
    for row in rows:
        store.save(fast_track_incident(row, thresholds={"lower": 0.59, "upper": UPPER, "source": "approved"}))
    first = apply_to_store(tmp_path / "i.db", scored)
    second = apply_to_store(tmp_path / "i.db", scored)
    assert first["updated"] == second["updated"] == 3
    for record in store.list(kind="fast_track"):
        assert record["priority"] == "HIGH"
        assert record["llm_called"] is False
        assert record["evidence"]["rule_check"]["outcome"] == OUTCOME_CONFIRM
        assert record["evidence"]["flows"]