# SOC Agent Research Patch 1: Isolate Provenance Effects

## Purpose
This patch makes provenance-related ablations independently measurable and ensures they appear in experiment summaries.

## Files to replace
Copy the files in `soc_agent/` over the matching files in your project's `soc_agent/` directory. Copy `tests/test_provenance.py` over the matching test file.

## Changes
- Adds `VerifierConfig.use_provenance_floor` to switch provenance-based risk-floor behavior independently of verifier provenance filtering.
- Adds `F_verifier_provenance`: verifier filters for valid signed evidence, while the provenance-based risk floor is disabled.
- Adds `G_full_provenance`: both verifier provenance filtering and the provenance-based risk floor are enabled.
- Includes both configurations in the main result table, per-family table, and paired comparisons.
- Adds a test that checks the independent configuration settings.

## Validation performed
- `python -m pytest -q`: 41 passed, 1 skipped.
- A tiny smoke evaluation (`--n 2 --seed 7`) confirmed both configurations appear in the report and paired-comparison table. This tiny run is a code/reporting check only; it is not statistically meaningful evidence and must not be used for research claims.

## Important
This patch does not establish novelty or prove that provenance improves outcomes. Run the full pre-registered/matched experiment on a sufficiently large held-out set and inspect per-case results. The hard-coded benchmark HMAC key is for synthetic experiments only, not production use.
