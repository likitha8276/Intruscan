"""Verifier configuration. Boolean flags exist so each module can be ablated."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta


@dataclass
class VerifierConfig:
    # --- thresholds (set on a calibration split, never on the test split) ---
    tau: float = 0.70                          # min chain confidence to be SUPPORTED
    max_age: timedelta = timedelta(hours=24)   # evidence older than this is stale
    clock_skew: timedelta = timedelta(minutes=5)
    contradiction_window: timedelta = timedelta(hours=1)
    single_source_penalty: float = 0.80        # applied to high-impact claims with 1 source
    
    # --- ablation switches (module on/off) ---
    check_order: bool = True        # temporal ordering of the chain
    check_freshness: bool = True    # stale / future timestamps
    check_integrity: bool = True    # single-source penalty, contradictions
    use_confidence: bool = True     # parser / entity-match confidence
    three_state: bool = True        # if False, UNKNOWN collapses to CONTRADICTED (binary baseline)

    # relations that directly contradict a relation between the same src/dst
    contradicts: dict[str, list[str]] = field(default_factory=lambda: {
        "login_success": ["login_blocked"],
        "exec": ["exec_blocked"],
        "file_write": ["write_blocked"],
        "connect": ["connect_blocked"],
    })

    require_provenance: bool =False
    provenance_key: bytes | None = None
