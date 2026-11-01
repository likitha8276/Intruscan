# Reproducibility Investigation — 24 October 2026

## Finding
The original simulation and a fresh rerun used the same seed (7), 40 scenarios per family, and 563 test cases. Baseline configurations A_raw, B_hardened, C_graph_binary, and E_abstain_only reproduced their headline unsafe rates.

## Full-system discrepancy
The original D_full results reported 7.4% unsafe outcomes and 16.5% clean-case escalation burden. The fresh rerun reported 5.2% unsafe outcomes and 65.8% clean-case escalation burden.

A case-level comparison found 101 D_full decisions changed from CLOSE to ESCALATE:
- Clean: 39
- Log attacks: 51
- Graph attacks: 8
- Joint attacks: 3

The changed outcomes were recorded as llm_closed in the original results and close_blocked_by_verification_unknown in the rerun.

## Interpretation
The current router blocks a CLOSE decision when verification is enabled, three-state verification is active, and the aggregate verdict is not SUPPORTED, provided the gate is enabled. The exact reason the original run behaved differently has not been established.

File modification timestamps suggest the source files may have changed after the original run, but timestamps do not prove which source version produced the original results.

## Reporting restriction
Do not describe the original D_full metrics as reproducible. Preserve both result folders. Keep simulated results separate from the small real-LLM pilot. Further conclusions require establishing the source-version difference or repeating evaluation under a documented, fixed source version.
