"""Risk-consistency gate: do the proposed severity/action fit the VERIFIED facts and policy?

Two jobs:
  1. a graph-derived severity floor (a verified full known pattern anchored on the alert -> 'high';
     a verified partial pattern with a high-risk step -> 'medium'). The LLM may not go below it,
     which is what stops a concealment ("close it") from silently succeeding.
  2. action checks: severity proportionate to a containment action, and the action's target must
     appear in a SUPPORTED claim whose chain contains a relation that justifies that action.

The floor only knows the defender's *known* templates. Held-out attack types are invisible to it.
"""
from __future__ import annotations

from datetime import datetime
from itertools import islice

from .config import VerifierConfig
from .graph_utils import all_events
from .models import CONTAINMENT, SEV_RANK, Alert, GateResult, ParsedOutput
from .patterns import HIGH_RISK_RELS, KNOWN_TEMPLATES, chain_from, find_bindings
from .schemas import Claim, Verdict, VerifyResult
from .verifier import verify_claim
from .provenance import verify_event

ACTION_REQUIRES_REL = {
    "isolate_host": {"exec", "remote_exec", "file_write", "encrypt", "connect"},
    "block_ip": {"connect", "http_post"},
    "disable_account": {"login_success", "priv_change", "file_read"},
}


def severity_floor(store, alert: Alert, now: datetime, vcfg: VerifierConfig,
                   max_bindings: int = 20) -> tuple[str | None, list[str]]:
    from itertools import combinations
    events = all_events(store)
    anchors = set(alert.entities)
    floor, evidence = None, []
    for t in KNOWN_TEMPLATES:
        n = len(t.steps)
        for size in range(n, 1, -1):
            for subset in combinations(range(n), size):
                if size < n and not any(t.steps[i][0] in HIGH_RISK_RELS for i in subset):
                    continue
                for b in islice(find_bindings(t, events, subset, anchors), max_bindings):
                    chain = chain_from(t, subset, b)
                    r = verify_claim(Claim("floor", t.name, chain, True), store, now, vcfg)
                    if r.verdict == Verdict.SUPPORTED:
                        if size == n:
                            return "high", [f"{t.name}:full"]
                        floor = "medium"
                        evidence.append(f"{t.name}:partial{list(subset)}")
                        break
    return floor, evidence

def corroborated_high_risk_floor(
    store, alert: Alert, vcfg: VerifierConfig
) -> tuple[str | None, list[str]]:
    """Flag corroborated high-risk events only when signatures are valid."""
    if vcfg.provenance_key is None:
        return None, []

    anchors = set(alert.entities)
    events = all_events(store)

    candidates = [
        event
        for event in events
        if event.rel in HIGH_RISK_RELS
        and (event.src in anchors or event.dst in anchors)
        and event.parse_conf >= 0.90
        and event.match_conf >= 0.90
        and event.source_system not in {"", "unknown"}
        and verify_event(event, vcfg.provenance_key)
    ]

    source_systems = {event.source_system for event in candidates}

    if len(candidates) >= 2 and len(source_systems) >= 2:
        return "medium", [
            f"corroborated_high_risk_events:{len(candidates)}:"
            f"{len(source_systems)}_sources"
        ]

    return None, []


def risk_gate(parsed: ParsedOutput, verifs: list[VerifyResult], store, alert: Alert,
              now: datetime, vcfg: VerifierConfig) -> GateResult:
    g = GateResult()
    g.floor, g.floor_evidence = severity_floor(store, alert, now, vcfg)
    fallback_floor, fallback_evidence = (
        corroborated_high_risk_floor(store, alert, vcfg)
        if vcfg.use_provenance_floor else (None, [])
    )
    if fallback_floor is not None:
        if g.floor is None or SEV_RANK[fallback_floor]> SEV_RANK[g.floor]:
            g.floor = fallback_floor
        g.floor_evidence.extend(fallback_evidence)
    llm_sev = SEV_RANK[parsed.severity]
    if g.floor is not None and (llm_sev < SEV_RANK[g.floor] or parsed.action.type == "close"):
        g.flags.append(f"under_escalation(floor={g.floor},llm={parsed.severity}/{parsed.action.type})")

    a = parsed.action
    if a.type in CONTAINMENT:
        if llm_sev < SEV_RANK["high"]:
            g.flags.append("action_exceeds_severity")
        need = ACTION_REQUIRES_REL[a.type]
        justified = False
        for claim, res in zip(parsed.claims, verifs):
            if res.verdict != Verdict.SUPPORTED:
                continue
            ents = {e for s in claim.chain for e in (s.src, s.dst)}
            if a.target in ents and any(s.rel in need for s in claim.chain):
                justified = True
        if not justified:
            g.flags.append("action_not_justified_by_verified_claims")
    g.ok = not g.flags
    return g
