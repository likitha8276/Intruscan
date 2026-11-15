"""Deterministic temporal evidence-chain verifier.

No LLM is involved. For each claim, every step of its chain must be found in
the evidence graph, in time order, fresh, uncontradicted, and with enough
confidence. The result is Supported / Contradicted / Unknown.

Precedence: any CONTRADICTED step wins; otherwise any gap makes it UNKNOWN;
only a fully clean chain is SUPPORTED.
"""
from __future__ import annotations

from datetime import datetime

from .config import VerifierConfig
from .evidence_store import EvidenceReader
from .schemas import Claim, Event, StepResult, Verdict, VerifyResult
from .provenance import verify_event


def _contradiction(
    store: EvidenceReader,
    step,
    anchor: Event,
    cfg: VerifierConfig,
) -> Event | None:
    """Find a contradicting edge on the same src/dst near the anchor event."""
    for bad_rel in cfg.contradicts.get(step.rel, []):
        for ev in store.find(bad_rel, step.src, step.dst):
            if abs(ev.ts - anchor.ts) <= cfg.contradiction_window:
                return ev
    return None


def verify_claim(
    claim: Claim,
    store: EvidenceReader,
    now: datetime,
    cfg: VerifierConfig | None = None,
) -> VerifyResult:
    cfg = cfg or VerifierConfig()
    result = VerifyResult(claim_id=claim.id, verdict=Verdict.SUPPORTED)

    if not claim.chain:
        result.verdict = Verdict.UNKNOWN
        result.reasons.append("empty_chain")
        return result

    if cfg.require_provenance and cfg.provenance_key is None:
        result.verdict = Verdict.UNKNOWN
        result.reasons.append("provenance_key_missing")
        return result

    candidate_groups: list[list[tuple[Event, float, int]]] = []
    step_statuses: list[tuple[str, str | None]] = []
    contradicted = False
    unknown = False

    # Collect fresh, provenance-valid, uncontradicted candidates per step.
    for step in claim.chain:
        candidates = store.find(step.rel, step.src, step.dst)

        if cfg.require_provenance:
            candidates = [
                ev for ev in candidates
                if verify_event(ev, cfg.provenance_key)
            ]

        if not candidates:
            candidate_groups.append([])
            step_statuses.append(("missing", None))
            result.reasons.append(
                f"missing_link:{step.rel}({step.src}->{step.dst})"
            )
            unknown = True
            continue

        valid_events: list[Event] = []
        rejected_status: tuple[str, str] | None = None

        for ev in candidates:
            if cfg.check_freshness:
                if ev.ts > now + cfg.clock_skew:
                    rejected_status = rejected_status or ("future_ts", ev.event_id)
                    continue
                if now - ev.ts > cfg.max_age:
                    rejected_status = rejected_status or ("stale", ev.event_id)
                    continue

            if cfg.check_integrity:
                bad = _contradiction(store, step, ev, cfg)
                if bad is not None:
                    rejected_status = ("contradicted", ev.event_id)
                    result.reasons.append(f"contradicted_by:{bad.event_id}")
                    continue

            valid_events.append(ev)

        # Count only candidates that passed provenance, freshness, and integrity.
        n_sources = len({ev.source_system for ev in valid_events})
        fresh_candidates: list[tuple[Event, float, int]] = []

        for ev in valid_events:
            confidence = (
                min(ev.parse_conf, ev.match_conf)
                if cfg.use_confidence
                else 1.0
            )

            if cfg.check_integrity and claim.high_impact and n_sources < 2:
                confidence *= cfg.single_source_penalty

            fresh_candidates.append((ev, confidence, n_sources))

        if not fresh_candidates:
            candidate_groups.append([])
            if rejected_status is None:
                rejected_status = ("missing", "")
            status, event_id = rejected_status
            step_statuses.append((status, event_id or None))

            if status == "contradicted":
                contradicted = True
            elif status == "future_ts":
                unknown = True
                result.reasons.append(f"future_timestamp:{event_id}")
            elif status == "stale":
                unknown = True
                result.reasons.append(f"stale:{event_id}")
            else:
                unknown = True
            continue

        candidate_groups.append(fresh_candidates)
        step_statuses.append(("ok", None))

    # Build chronological paths. Each state stores its weakest and total
    # confidence so the final choice matches VerifyResult's min-confidence rule.
    states: list[tuple[list[tuple[int, Event, float, int]], float, float]] = [
        ([], float("inf"), 0.0)
    ]

    for index, group in enumerate(candidate_groups):
        if not group:
            continue

        next_states = []

        for ev, confidence, n_sources in group:
            candidate_states = []

            for path, min_confidence, total_confidence in states:
                previous_event = path[-1][1] if path else None
                if (
                    cfg.check_order
                    and previous_event is not None
                    and ev.ts < previous_event.ts
                ):
                    continue

                candidate_states.append((
                    path + [(index, ev, confidence, n_sources)],
                    min(min_confidence, confidence),
                    total_confidence + confidence,
                ))

            # Keep the Pareto frontier for paths ending at this candidate.
            frontier = []
            for state in candidate_states:
                _, state_min, state_total = state
                dominated = any(
                    other_min >= state_min
                    and other_total >= state_total
                    and (other_min > state_min or other_total > state_total)
                    for _, other_min, other_total in frontier
                )
                if dominated:
                    continue

                frontier = [
                    other for other in frontier
                    if not (
                        state_min >= other[1]
                        and state_total >= other[2]
                        and (state_min > other[1] or state_total > other[2])
                    )
                ]
                frontier.append(state)

            next_states.extend(frontier)

        if not next_states:
            step = claim.chain[index]
            event_id = group[0][0].event_id
            step_statuses[index] = ("out_of_order", event_id)
            result.reasons.append(f"out_of_order:{step.rel}")
            contradicted = True
            continue

        states = next_states

    # Prefer the strongest weakest link; use total confidence as a tie-breaker.
    best_path, _, _ = max(states, key=lambda state: (state[1], state[2]))
    selected = {
        index: (ev, confidence, n_sources)
        for index, ev, confidence, n_sources in best_path
    }

    confidences = []
    for index, step in enumerate(claim.chain):
        if index in selected:
            ev, confidence, n_sources = selected[index]
            result.steps.append(
                StepResult(step, "ok", ev.event_id, confidence, n_sources)
            )
            confidences.append(confidence)
        else:
            status, event_id = step_statuses[index]
            result.steps.append(StepResult(step, status, event_id))
            if status in ("missing", "stale", "future_ts"):
                unknown = True
            elif status in ("contradicted", "out_of_order"):
                contradicted = True

    result.confidence = min(confidences) if confidences else 0.0

    if contradicted:
        result.verdict = Verdict.CONTRADICTED
    elif unknown:
        result.verdict = Verdict.UNKNOWN
    elif cfg.use_confidence and result.confidence < cfg.tau:
        result.verdict = Verdict.UNKNOWN
        result.reasons.append(
            f"low_confidence:{result.confidence:.2f}<{cfg.tau}"
        )
    else:
        result.verdict = Verdict.SUPPORTED

    if not cfg.three_state and result.verdict == Verdict.UNKNOWN:
        result.verdict = Verdict.CONTRADICTED
        result.reasons.append("binary_mode:unknown_collapsed")

    return result
