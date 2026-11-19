import json
import pytest
from soc_agent.agent import (AgentConfig, SOCAgent, event_from_dict,
                             scenario_from_store)
from soc_agent.evidence_store import EvidenceStore

GOOD = [{"rel": "flow", "src": "10.0.0.1", "dst": "10.0.0.2"}]
BAD = [{"rel": "flow", "src": "10.0.0.9", "dst": "10.0.0.8"}]
TOOL = json.dumps({"tool": "expand_graph", "args": {"entity": "10.0.0.1"}})


def verdict(chain):
    return json.dumps({"severity": "low",
                       "action": {"type": "investigate", "target": ""},
                       "claims": [{"id": "c1", "text": "t", "chain": chain}]})


class Seq:
    last_usage = {}

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def generate(self, system, user, seed_key=""):
        self.calls.append(user)
        return self.replies[min(len(self.calls) - 1, len(self.replies) - 1)]


@pytest.fixture
def scn(monkeypatch):
    monkeypatch.setenv("SOC_PROVENANCE_KEY", "")
    store = EvidenceStore()
    store.add_event(event_from_dict({
        "event_id": "e1", "ts": "2016-08-29T00:12:21Z", "rel": "flow",
        "src": "10.0.0.1", "dst": "10.0.0.2"}))
    return scenario_from_store(store, ("10.0.0.1", "10.0.0.2"),
                               logs={"e1": "log line"})


def agent(llm, **kw):
    return SOCAgent(llm, AgentConfig(name="t", **kw))


def test_tool_then_answer(scn):
    llm = Seq(TOOL, verdict(GOOD))
    res = agent(llm, agentic=True).run(scn)
    assert len(llm.calls) == 2
    assert "TOOL RESULTS" in llm.calls[1]
    assert res.verdicts == ["SUPPORTED"]


def test_step_cap_forces_stop(scn):
    llm = Seq(TOOL)
    res = agent(llm, agentic=True, max_tool_steps=2).run(scn)
    assert len(llm.calls) == 3
    assert res.parsed_ok is False


def test_disabled_makes_one_call(scn):
    llm = Seq(TOOL)
    agent(llm, agentic=False).run(scn)
    assert len(llm.calls) == 1


def test_revision_after_unsupported_claim(scn):
    llm = Seq(verdict(BAD), verdict(GOOD))
    res = agent(llm, agentic=True).run(scn)
    assert len(llm.calls) == 2
    assert "VERIFIER FEEDBACK" in llm.calls[1]
    assert res.verdicts == ["SUPPORTED"]