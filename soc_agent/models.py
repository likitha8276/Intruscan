"""Agent-level data types (alerts, LLM output, gate result, final decision)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .schemas import Claim


class Outcome(str, Enum):
    PROPOSE = "PROPOSE"      # containment action proposed (still needs human approval)
    ESCALATE = "ESCALATE"    # sent to an analyst with a recorded reason
    CLOSE = "CLOSE"          # alert dismissed as benign


SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONTAINMENT = ("isolate_host", "block_ip", "disable_account")
ACTION_TYPES = ("close", "investigate") + CONTAINMENT


@dataclass(frozen=True)
class Alert:
    alert_id: str
    ts: datetime
    entities: tuple[str, ...]
    description: str = ""


@dataclass
class Action:
    type: str
    target: str = ""


@dataclass
class ParsedOutput:
    claims: list[Claim]
    severity: str
    action: Action
    raw: str = ""


@dataclass
class GateResult:
    ok: bool = True
    flags: list[str] = field(default_factory=list)
    floor: str | None = None                 # severity floor derived from verified graph facts
    floor_evidence: list[str] = field(default_factory=list)


@dataclass
class Decision:
    outcome: Outcome
    action: Action | None
    reasons: list[str] = field(default_factory=list)
