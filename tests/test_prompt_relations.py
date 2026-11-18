"""D_full_rel: the analyst prompt can list the relations that the evidence graph actually contains.

Background: a real Groq run on bridge output produced a chain step with rel "unauthorized_pair".
The bridge only emits "connect" and "baseline_connect" events, so the verifier could not support
the claim (missing_link) and the risk gate escalated. Telling the model which relations exist
removes the cause; the verifier itself is unchanged.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from soc_agent.config import VerifierConfig
from soc_agent.evaluate import MAIN, make_configs
from soc_agent.evidence_store import EvidenceStore
from soc_agent.models import Alert
from soc_agent.prompts import build_prompt
from soc_agent.schemas import ChainStep, Claim, Event, Verdict
from soc_agent.verifier import verify_claim

NOW = datetime(2026, 11, 3, 10, 5, tzinfo=timezone.utc)


def _events():
    return [
        Event("e1", NOW - timedelta(minutes=3), "connect", "172.16.0.1", "192.168.10.50", "netflow"),
        Event("e2", NOW - timedelta(minutes=2), "connect", "172.16.0.1", "192.168.10.50", "netflow"),
        Event("e3", NOW - timedelta(minutes=9), "baseline_connect", "192.168.10.5", "192.168.10.3", "netflow_baseline"),
    ]


def _alert():
    return Alert("a1", NOW, ("172.16.0.1",), "suspicious flows")


def test_default_prompt_has_no_relation_list():
    _, user = build_prompt(_alert(), _events(), [], hardened=True)
    assert "ALLOWED RELATIONS" not in user


def test_relation_list_names_only_relations_present():
    _, user = build_prompt(_alert(), _events(), [], hardened=True, list_relations=True)
    line = next(ln for ln in user.splitlines() if ln.startswith("ALLOWED RELATIONS"))
    assert "baseline_connect, connect." in line
    assert "unauthorized_pair" not in user


def test_no_events_means_no_relation_list():
    _, user = build_prompt(_alert(), [], [], hardened=True, list_relations=True)
    assert "ALLOWED RELATIONS" not in user


def test_system_prompt_is_unchanged_by_the_flag():
    s_off, _ = build_prompt(_alert(), _events(), [], hardened=True)
    s_on, _ = build_prompt(_alert(), _events(), [], hardened=True, list_relations=True)
    assert s_off == s_on


def test_frozen_configs_unchanged_and_rel_config_differs_only_by_flag():
    cfgs = make_configs(VerifierConfig())
    for name in MAIN:
        assert cfgs[name].list_relations is False
    assert cfgs["D_full_rel"].list_relations is True
    assert replace(cfgs["D_full_rel"], name="D_full", list_relations=False) == cfgs["D_full"]


def test_invented_relation_is_still_not_supported():
    store = EvidenceStore()
    for e in _events():
        store.add_event(e)
    claim = Claim("c1", "unauthorized pair", [ChainStep("unauthorized_pair", "172.16.0.1", "192.168.10.50")])
    result = verify_claim(claim, store, NOW)
    assert result.verdict == Verdict.UNKNOWN
    assert any(r.startswith("missing_link:unauthorized_pair") for r in result.reasons)
