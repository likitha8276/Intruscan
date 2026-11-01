
"""The SOC agent: select -> analyst LLM -> verify -> risk gate -> route (LangGraph).

Every stage is a plain method, so the same logic runs under LangGraph or, if langgraph is
not installed, as a sequential fallback. The LLM has no execution authority: it only
proposes, and PROPOSE still means "awaiting human approval".
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, TypedDict

from .config import VerifierConfig
from .models import CONTAINMENT, SEV_RANK, Decision, GateResult
from .patterns import REL_RISK
from .prompts import build_prompt, parse_output
from .risk_gate import risk_gate
from .router import route
from .scenarios import Scenario
from .selector import full_context, select_subgraph
from .verifier import verify_claim

try:  # LangGraph is optional at import time
    from langgraph.graph import END, StateGraph
    HAVE_LANGGRAPH = True
except Exception:  # pragma: no cover
    HAVE_LANGGRAPH = False


@dataclass
class AgentConfig:
    name: str
    hardened: bool = True
    use_selector: bool = True
    use_verifier: bool = True
    use_gate: bool = True
    verifier: VerifierConfig = field(default_factory=VerifierConfig)
    token_budget: int = 1200
    hops: int = 2
    max_log_lines: int = 16


class State(TypedDict, total=False):
    scn: Scenario
    events: list
    logs: list
    system: str
    user: str
    raw: str
    parsed: Any
    verifs: list
    gate: GateResult
    decision: Decision
    llm_ms: float
    verify_ms: float
    usage: dict


@dataclass
class CaseResult:
    case_id: str
    config: str
    decision: Decision
    parsed_ok: bool
    llm_ms: float
    verify_ms: float
    prompt_tokens: int
    completion_tokens: int
    verdicts: list[str]
    gate_flags: list[str]


class SOCAgent:
    def __init__(self, llm, cfg: AgentConfig, use_langgraph: bool = True):
        self.llm, self.cfg = llm, cfg
        self.graph = (
            self._build_graph()
            if (use_langgraph and HAVE_LANGGRAPH)
            else None
        )

    # ------------------------------------------------------------ nodes
    def n_select(self, s: State) -> dict:
        scn, cfg = s["scn"], self.cfg

        if cfg.use_selector:
            events = select_subgraph(
                scn.store, scn.alert, scn.now,
                cfg.token_budget, cfg.hops,
            )
        else:
            events = full_context(scn.store)

        anchors = set(scn.alert.entities)
        cand = [e for e in events if e.event_id in scn.logs]

        # Alert-entity lines first, then by risk.
        cand.sort(
            key=lambda e: (
                0 if (e.src in anchors or e.dst in anchors) else 1,
                -REL_RISK.get(e.rel, 0.3),
                e.event_id,
            )
        )

        chosen = sorted(
            cand[:cfg.max_log_lines],
            key=lambda e: (e.ts, e.event_id),
        )

        return {
            "events": events,
            "logs": [scn.logs[e.event_id] for e in chosen],
        }

    def n_analyst(self, s: State) -> dict:
        scn = s["scn"]
        system, user = build_prompt(
            scn.alert, s["events"], s["logs"], self.cfg.hardened
        )

        t0 = time.perf_counter()
        raw = self.llm.generate(system, user, scn.case_id)
        ms = (time.perf_counter() - t0) * 1000
        usage = dict(getattr(self.llm, "last_usage", {}) or {})
        ms = usage.get("wall_ms", ms)

        return {
            "system": system,
            "user": user,
            "raw": raw,
            "parsed": parse_output(raw),
            "llm_ms": ms,
            "usage": usage,
        }

    def n_verify(self, s: State) -> dict:
        parsed, scn = s["parsed"], s["scn"]

        if not self.cfg.use_verifier:
            return {"verifs": [], "verify_ms": 0.0}

        t0 = time.perf_counter()
        high = (
            parsed.action.type in CONTAINMENT
            or SEV_RANK[parsed.severity] >= SEV_RANK["high"]
        )

        verifs = []
        for c in parsed.claims:
            c.high_impact = high
            verifs.append(
                verify_claim(
                    c, scn.store, scn.now, self.cfg.verifier
                )
            )

        return {
            "verifs": verifs,
            "verify_ms": (time.perf_counter() - t0) * 1000,
        }

    def n_gate(self, s: State) -> dict:
        if not (self.cfg.use_gate and self.cfg.use_verifier):
            return {"gate": GateResult()}

        t0 = time.perf_counter()
        scn = s["scn"]

        g = risk_gate(
            s["parsed"],
            s["verifs"],
            scn.store,
            scn.alert,
            scn.now,
            self.cfg.verifier,
        )

        return {
            "gate": g,
            "verify_ms": s.get("verify_ms", 0.0)
            + (time.perf_counter() - t0) * 1000,
        }

    def n_route(self, s: State) -> dict:
        d = route(
            s.get("parsed"),
            s.get("verifs", []),
            s.get("gate", GateResult()),
            self.cfg.use_verifier,
            self.cfg.verifier.three_state,
            use_gate=self.cfg.use_gate,
        )
        return {"decision": d}

    # ------------------------------------------------------------ wiring
    def _build_graph(self):
        g = StateGraph(State)
        g.add_node("select", self.n_select)
        g.add_node("analyst", self.n_analyst)
        g.add_node("verify", self.n_verify)
        g.add_node("gate", self.n_gate)
        g.add_node("route", self.n_route)

        g.set_entry_point("select")
        g.add_edge("select", "analyst")
        g.add_conditional_edges(
            "analyst",
            lambda s: "route" if s.get("parsed") is None else "verify",
            {"route": "route", "verify": "verify"},
        )
        g.add_edge("verify", "gate")
        g.add_edge("gate", "route")
        g.add_edge("route", END)

        return g.compile()

    def run(self, scn: Scenario) -> CaseResult:
        if self.graph is not None:
            s = self.graph.invoke({"scn": scn})
        else:
            s = {"scn": scn}
            s.update(self.n_select(s))
            s.update(self.n_analyst(s))

            if s["parsed"] is not None:
                s.update(self.n_verify(s))
                s.update(self.n_gate(s))

            s.update(self.n_route(s))

        gate = s.get("gate", GateResult())
        usage = s.get("usage", {})

        return CaseResult(
            scn.case_id,
            self.cfg.name,
            s["decision"],
            s.get("parsed") is not None,
            s.get("llm_ms", 0.0),
            s.get("verify_ms", 0.0),
            int(usage.get("prompt_tokens", 0)),
            int(usage.get("completion_tokens", 0)),
            [v.verdict.value for v in s.get("verifs", [])],
            list(gate.flags),
        )
