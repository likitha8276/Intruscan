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

def _contradiction(store: EvidenceReader, step, anchor: Event, cfg: VerifierConfig) -> Event | None:
    """An edge with a contradicting relation on the same src/dst near the anchor event."""
    for bad_rel in cfg.contradicts.get(step.rel, []):
        for ev in store.find(bad_rel, step.src, step.dst):
            if abs(ev.ts - anchor.ts) <= cfg.contradiction_window:
                return ev
    return None


def verify_claim(claim: Claim, store: EvidenceReader, now: datetime,
                 cfg: VerifierConfig | None = None) -> VerifyResult:
    cfg = cfg or VerifierConfig()
    result = VerifyResult(claim_id=claim.id, verdict=Verdict.SUPPORTED)
    contradicted = False
    unknown = False
    prev_ts: datetime | None = None
    confs: list[float] = []

    if not claim.chain:                       # a claim with no evidence is never supported
        result.verdict = Verdict.UNKNOWN
        result.reasons.append("empty_chain")
        return result

    for step in claim.chain:
        candidates = store.find(step.rel, step.src, step.dst)
        if cfg.require_provenance:
            if cfg.provenance_key is None:
                result.verdict = Verdict.UNKNOWN
                result.reasons.append("provenance_key_missing")
                return result

            candidates = [
                ev for ev in candidates
                if verify_event(ev, cfg.provenance_key)
            ]

        # 1. completeness: required link must exist
        if not candidates:
            result.steps.append(StepResult(step, "missing"))
            result.reasons.append(f"missing_link:{step.rel}({step.src}->{step.dst})")
            unknown = True
            continue

        # 2. temporal order: earliest candidate that does not precede the previous step
        if cfg.check_order and prev_ts is not None:
            ordered = [e for e in candidates if e.ts >= prev_ts]
            if not ordered:
                result.steps.append(StepResult(step, "out_of_order", candidates[0].event_id))
                result.reasons.append(f"out_of_order:{step.rel}")
                contradicted = True
                continue
            ev = ordered[0]
        else:
            ev = candidates[0]

        # 3. freshness: stale evidence or timestamps from the future
        if cfg.check_freshness:
            if ev.ts > now + cfg.clock_skew:
                result.steps.append(StepResult(step, "future_ts", ev.event_id))
                result.reasons.append(f"future_timestamp:{ev.event_id}")
                unknown = True
                continue
            if now - ev.ts > cfg.max_age:
                result.steps.append(StepResult(step, "stale", ev.event_id))
                result.reasons.append(f"stale:{ev.event_id}")
                unknown = True
                continue

        # 4. integrity: direct contradiction in the graph
        if cfg.check_integrity:
            bad = _contradiction(store, step, ev, cfg)
            if bad is not None:
                result.steps.append(StepResult(step, "contradicted", ev.event_id))
                result.reasons.append(f"contradicted_by:{bad.event_id}")
                contradicted = True
                continue

        # 5. provenance + extraction confidence
        n_sources = len({e.source_system for e in candidates})
        conf = 1.0
        if cfg.use_confidence:
            conf = min(ev.parse_conf, ev.match_conf)
        if cfg.check_integrity and claim.high_impact and n_sources < 2:
            conf *= cfg.single_source_penalty
        confs.append(conf)
        result.steps.append(StepResult(step, "ok", ev.event_id, conf, n_sources))
        prev_ts = ev.ts

    result.confidence = min(confs) if confs else 0.0

    if contradicted:
        result.verdict = Verdict.CONTRADICTED
    elif unknown:
        result.verdict = Verdict.UNKNOWN
    elif cfg.use_confidence and result.confidence < cfg.tau:
        result.verdict = Verdict.UNKNOWN
        result.reasons.append(f"low_confidence:{result.confidence:.2f}<{cfg.tau}")
    else:
        result.verdict = Verdict.SUPPORTED

    # binary baseline for ablation: no abstention state
    if not cfg.three_state and result.verdict == Verdict.UNKNOWN:
        result.verdict = Verdict.CONTRADICTED
        result.reasons.append("binary_mode:unknown_collapsed")

    return result
