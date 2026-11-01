from datetime import datetime, timedelta, timezone

import pytest

from soc_agent.config import VerifierConfig
from soc_agent.evidence_store import EvidenceStore
from soc_agent.schemas import ChainStep, Claim, Event, Verdict
from soc_agent.verifier import verify_claim

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


def t(minutes_ago: int) -> datetime:
    return NOW - timedelta(minutes=minutes_ago)


def ev(eid, rel, src, dst, minutes_ago, source="edr", parse=0.95, match=0.95):
    return Event(eid, t(minutes_ago), rel, src, dst, source, parse, match)


def base_store():
    s = EvidenceStore()
    s.add_event(ev("e1", "login_fail", "10.0.0.5", "host-a", 30))
    s.add_event(ev("e2", "login_success", "10.0.0.5", "host-a", 20))
    s.add_event(ev("e3", "exec", "host-a", "powershell", 10))
    # a second source corroborates the key step
    s.add_event(ev("e2b", "login_success", "10.0.0.5", "host-a", 20, source="siem"))
    return s


CHAIN = [
    ChainStep("login_fail", "10.0.0.5", "host-a"),
    ChainStep("login_success", "10.0.0.5", "host-a"),
    ChainStep("exec", "host-a", "powershell"),
]


def claim(chain=CHAIN, high=True):
    return Claim("c1", "host-a compromised via brute force", chain, high_impact=high)


def test_complete_chain_supported():
    r = verify_claim(claim(), base_store(), NOW)
    assert r.verdict == Verdict.SUPPORTED, r.reasons


def test_deleted_edge_gives_unknown():
    s = base_store()
    s.remove_event("e2")
    s.remove_event("e2b")
    r = verify_claim(claim(), s, NOW)
    assert r.verdict == Verdict.UNKNOWN
    assert any(x.startswith("missing_link") for x in r.reasons)


def test_reordered_events_contradicted():
    s = EvidenceStore()
    s.add_event(ev("e1", "login_fail", "10.0.0.5", "host-a", 10))
    s.add_event(ev("e2", "login_success", "10.0.0.5", "host-a", 20))   # before the fail
    s.add_event(ev("e3", "exec", "host-a", "powershell", 5))
    r = verify_claim(claim(), s, NOW)
    assert r.verdict == Verdict.CONTRADICTED
    assert any(x.startswith("out_of_order") for x in r.reasons)


def test_stale_evidence_unknown():
    s = EvidenceStore()
    s.add_event(ev("e1", "login_fail", "10.0.0.5", "host-a", 60 * 48))
    r = verify_claim(claim([CHAIN[0]]), s, NOW)
    assert r.verdict == Verdict.UNKNOWN
    assert any(x.startswith("stale") for x in r.reasons)


def test_future_timestamp_unknown():
    s = EvidenceStore()
    s.add_event(ev("e1", "login_fail", "10.0.0.5", "host-a", -120))   # 2h in the future
    r = verify_claim(claim([CHAIN[0]]), s, NOW)
    assert r.verdict == Verdict.UNKNOWN
    assert any(x.startswith("future_timestamp") for x in r.reasons)


def test_low_parser_confidence_unknown():
    s = EvidenceStore()
    s.add_event(ev("e1", "login_fail", "10.0.0.5", "host-a", 30, parse=0.40))
    r = verify_claim(claim([CHAIN[0]], high=False), s, NOW)
    assert r.verdict == Verdict.UNKNOWN
    assert any(x.startswith("low_confidence") for x in r.reasons)


def test_direct_contradiction():
    s = base_store()
    s.add_event(ev("b1", "login_blocked", "10.0.0.5", "host-a", 19))
    r = verify_claim(claim(), s, NOW)
    assert r.verdict == Verdict.CONTRADICTED
    assert any(x.startswith("contradicted_by") for x in r.reasons)


def test_single_source_penalty_pushes_high_impact_to_unknown():
    s = EvidenceStore()
    s.add_event(ev("e1", "login_fail", "10.0.0.5", "host-a", 30, parse=0.85, match=0.85))
    high = verify_claim(claim([CHAIN[0]], high=True), s, NOW)
    low = verify_claim(claim([CHAIN[0]], high=False), s, NOW)
    assert high.verdict == Verdict.UNKNOWN      # 0.85 * 0.8 = 0.68 < 0.70
    assert low.verdict == Verdict.SUPPORTED


def test_empty_chain_never_supported():
    r = verify_claim(claim([]), base_store(), NOW)
    assert r.verdict == Verdict.UNKNOWN


# ---- ablation behaviour: disabling a module must change outcomes ----

def test_ablation_no_order_check_accepts_reordered_chain():
    s = EvidenceStore()
    s.add_event(ev("e1", "login_fail", "10.0.0.5", "host-a", 10))
    s.add_event(ev("e2", "login_success", "10.0.0.5", "host-a", 20))
    s.add_event(ev("e3", "exec", "host-a", "powershell", 5))
    s.add_event(ev("e2b", "login_success", "10.0.0.5", "host-a", 20, source="siem"))
    cfg = VerifierConfig(check_order=False)
    r = verify_claim(claim(), s, NOW, cfg)
    assert r.verdict == Verdict.SUPPORTED       # unsafe acceptance the full system prevents


def test_ablation_binary_mode_collapses_unknown():
    s = base_store()
    s.remove_event("e2")
    s.remove_event("e2b")
    r = verify_claim(claim(), s, NOW, VerifierConfig(three_state=False))
    assert r.verdict == Verdict.CONTRADICTED
