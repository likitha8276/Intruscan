"""Core data contracts for the SOC verifier.

Agree on these with the ingestion / GraphRAG teammates: the Event shape is
what the graph must store, and Claim is what the LLM must emit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Verdict(str, Enum):
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Event:
    """One time-stamped fact in the evidence graph (an edge src -> dst)."""
    event_id: str
    ts: datetime
    rel: str                  # e.g. "login_fail", "login_success", "exec"
    src: str
    dst: str
    source_system: str = "unknown"   # e.g. "edr", "siem", "netflow"
    parse_conf: float = 1.0          # confidence the parser extracted this correctly
    match_conf: float = 1.0          # confidence entity resolution linked the right entities
    provenance_signature: str | None = None

@dataclass(frozen=True)
class ChainStep:
    """One required fact in a claim's evidence chain."""
    rel: str
    src: str
    dst: str


@dataclass
class Claim:
    """A claim proposed by the LLM, with the evidence chain it relies on."""
    id: str
    text: str
    chain: list[ChainStep]
    high_impact: bool = False        # e.g. "host compromised", "isolate host"


@dataclass
class StepResult:
    step: ChainStep
    status: str                      # ok | missing | out_of_order | stale | contradicted | future_ts | low_conf
    event_id: str | None = None
    confidence: float = 0.0
    n_sources: int = 0


@dataclass
class VerifyResult:
    claim_id: str
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    confidence: float = 0.0
    steps: list[StepResult] = field(default_factory=list)
