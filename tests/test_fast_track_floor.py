from soc_agent.incidents import apply_fast_track_floor


def test_floor_forces_escalate():
    r = apply_fast_track_floor({"outcome": "CLOSE", "reasons": ["x"]})
    assert r["outcome"] == "ESCALATE"
    assert r["agent_outcome_original"] == "CLOSE"
    assert "fast_track_floor_escalate" in r["reasons"]


def test_floor_keeps_escalate_unchanged():
    r = apply_fast_track_floor({"outcome": "ESCALATE", "reasons": ["x"]})
    assert r["outcome"] == "ESCALATE"
    assert "agent_outcome_original" not in r
