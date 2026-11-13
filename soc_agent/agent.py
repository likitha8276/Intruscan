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
from .llm import LLMProviderError, LLMUnavailableError
from .models import CONTAINMENT, SEV_RANK, Decision, GateResult, Outcome
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
    llm_error: str


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
        try:
            raw = self.llm.generate(system, user, scn.case_id)
        except (LLMUnavailableError, LLMProviderError) as exc:
            # Provider failures must never be interpreted as a benign analysis.
            # Catch only known provider errors; programming errors still surface.
            ms = (time.perf_counter() - t0) * 1000
            provider = getattr(exc, "provider", "llm")
            return {
                "system": system,
                "user": user,
                "raw": "",
                "parsed": None,
                "llm_ms": ms,
                "usage": {},
                "llm_error": f"{provider}: {exc}",
            }

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
            "llm_error": "",
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
        for claim in parsed.claims:
            claim.high_impact = high
            verifs.append(
                verify_claim(
                    claim, scn.store, scn.now, self.cfg.verifier
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

        gate = risk_gate(
            s["parsed"],
            s["verifs"],
            scn.store,
            scn.alert,
            scn.now,
            self.cfg.verifier,
        )

        return {
            "gate": gate,
            "verify_ms": s.get("verify_ms", 0.0)
            + (time.perf_counter() - t0) * 1000,
        }

    def n_route(self, s: State) -> dict:
        if s.get("llm_error"):
            return {
                "decision": Decision(
                    Outcome.ESCALATE,
                    None,
                    ["llm_unavailable"],
                )
            }

        decision = route(
            s.get("parsed"),
            s.get("verifs", []),
            s.get("gate", GateResult()),
            self.cfg.use_verifier,
            self.cfg.verifier.three_state,
            use_gate=self.cfg.use_gate,
        )
        return {"decision": decision}

    # ------------------------------------------------------------ wiring
    def _build_graph(self):
        graph = StateGraph(State)
        graph.add_node("select", self.n_select)
        graph.add_node("analyst", self.n_analyst)
        graph.add_node("verify", self.n_verify)
        graph.add_node("gate", self.n_gate)
        graph.add_node("route", self.n_route)

        graph.set_entry_point("select")
        graph.add_edge("select", "analyst")
        graph.add_conditional_edges(
            "analyst",
            lambda state: (
                "route" if state.get("parsed") is None else "verify"
            ),
            {"route": "route", "verify": "verify"},
        )
        graph.add_edge("verify", "gate")
        graph.add_edge("gate", "route")
        graph.add_edge("route", END)

        return graph.compile()

    def run(self, scn: Scenario) -> CaseResult:
        if self.graph is not None:
            state = self.graph.invoke({"scn": scn})
        else:
            state = {"scn": scn}
            state.update(self.n_select(state))
            state.update(self.n_analyst(state))

            if state["parsed"] is not None:
                state.update(self.n_verify(state))
                state.update(self.n_gate(state))

            state.update(self.n_route(state))

        gate = state.get("gate", GateResult())
        usage = state.get("usage", {})

        return CaseResult(
            scn.case_id,
            self.cfg.name,
            state["decision"],
            state.get("parsed") is not None,
            state.get("llm_ms", 0.0),
            state.get("verify_ms", 0.0),
            int(usage.get("prompt_tokens", 0)),
            int(usage.get("completion_tokens", 0)),
            [verif.verdict.value for verif in state.get("verifs", [])],
            list(gate.flags),
        )
