

"""Risk-consistency gate: do proposed severity/actions fit verified facts and policy?"""
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


def severity_floor(
    store,
    alert: Alert,
    now: datetime,
    vcfg: VerifierConfig,
    max_bindings: int = 20,
) -> tuple[str | None, list[str]]:
    from itertools import combinations

    events = all_events(store)
    anchors = set(alert.entities)
    floor, evidence = None, []

    for template in KNOWN_TEMPLATES:
        n = len(template.steps)
        for size in range(n, 1, -1):
            for subset in combinations(range(n), size):
                if size < n and not any(
                    template.steps[i][0] in HIGH_RISK_RELS
                    for i in subset
                ):
                    continue

                bindings = find_bindings(
                    template, events, subset, anchors
                )
                for binding in islice(bindings, max_bindings):
                    chain = chain_from(template, subset, binding)
                    result = verify_claim(
                        Claim("floor", template.name, chain, True),
                        store,
                        now,
                        vcfg,
                    )

                    if result.verdict == Verdict.SUPPORTED:
                        if size == n:
                            return "high", [f"{template.name}:full"]

                        floor = "medium"
                        evidence.append(
                            f"{template.name}:partial{list(subset)}"
                        )
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


def risk_gate(
    parsed: ParsedOutput,
    verifs: list[VerifyResult],
    store,
    alert: Alert,
    now: datetime,
    vcfg: VerifierConfig,
) -> GateResult:
    g = GateResult()

    g.floor, g.floor_evidence = severity_floor(
        store, alert, now, vcfg
    )

    fallback_floor, fallback_evidence = corroborated_high_risk_floor(
        store, alert, vcfg
    )

    if fallback_floor is not None:
        if (
            g.floor is None
            or SEV_RANK[fallback_floor] > SEV_RANK[g.floor]
        ):
            g.floor = fallback_floor

        g.floor_evidence.extend(fallback_evidence)

    llm_sev = SEV_RANK[parsed.severity]

    if g.floor is not None and (
        llm_sev < SEV_RANK[g.floor]
        or parsed.action.type == "close"
    ):
        g.flags.append(
            f"under_escalation(floor={g.floor},"
            f"llm={parsed.severity}/{parsed.action.type})"
        )

    action = parsed.action

    if action.type in CONTAINMENT:
        if llm_sev < SEV_RANK["high"]:
            g.flags.append("action_exceeds_severity")

        required_relations = ACTION_REQUIRES_REL[action.type]
        justified = False

        for claim, result in zip(parsed.claims, verifs):
            if result.verdict != Verdict.SUPPORTED:
                continue

            # The allowed relation and target must occur in the same step.
            if any(
                step.rel in required_relations
                and action.target in (step.src, step.dst)
                for step in claim.chain
            ):
                justified = True
                break

        if not justified:
            g.flags.append(
                "action_not_justified_by_verified_claims"
            )

    g.ok = not g.flags
    return g
