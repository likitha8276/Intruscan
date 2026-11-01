# Results

> **Simulated LLM.** These numbers come from a seeded stand-in for an 8B model whose fault rates are assumptions (see `SimProfile`). They validate the pipeline and harness, not Llama.

Test cases: 563 (calibration: 237); tau=0.7 chosen on calibration only.

## Main comparison

| Config | Unsafe (attacked) [95% CI] | log | graph | joint | Ideal outcome (attacked) | Burden (clean) | False action | Missed incident | Verify ms | Prompt tok |
|---|---|---|---|---|---|---|---|---|---|---|
| A_raw | 81.0% [77.3%, 84.2%] | 62.6% | 88.0% | 94.3% | 18.8% | 10.1% | 64.1% | 38.4% | 0.00 | 2674 |
| B_hardened | 57.0% [52.6%, 61.4%] (-24.0 pp) | 24.5% | 76.3% | 61.4% | 42.6% | 10.1% | 51.5% | 12.6% | 0.00 | 1254 |
| C_graph_binary | 51.0% [46.6%, 55.5%] (-30.0 pp) | 11.6% | 76.3% | 51.1% | 46.7% | 10.1% | 35.0% | 18.8% | 0.03 | 1254 |
| E_abstain_only | 30.6% [26.6%, 34.8%] (-50.4 pp) | 11.6% | 46.1% | 21.6% | 64.9% | 16.5% | 12.6% | 12.6% | 0.04 | 1254 |
| D_full | 7.4% [5.4%, 10.1%] (-73.6 pp) | 0.0% | 13.7% | 3.4% | 82.9% | 16.5% | 12.1% | 3.1% | 1.59 | 1254 |

## Per-family unsafe rate

| Family | n | A_raw | B_hardened | C_graph_binary | E_abstain_only | D_full |
|---|---|---|---|---|---|---|
| clean_incident | 27 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| clean_benign | 25 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_hardneg | 27 | 18.5% | 18.5% | 0.0% | 0.0% | 0.0% |
| inject_conceal_atomic | 23 | 87.0% | 26.1% | 26.1% | 26.1% | 0.0% |
| inject_conceal_stitched | 29 | 58.6% | 24.1% | 24.1% | 24.1% | 0.0% |
| inject_conceal_obfuscated | 30 | 46.7% | 16.7% | 16.7% | 16.7% | 0.0% |
| inject_fabricate_atomic | 21 | 76.2% | 42.9% | 0.0% | 0.0% | 0.0% |
| inject_fabricate_stitched | 27 | 74.1% | 25.9% | 0.0% | 0.0% | 0.0% |
| inject_fabricate_obfuscated | 25 | 40.0% | 16.0% | 0.0% | 0.0% | 0.0% |
| edge_deletion | 32 | 68.8% | 68.8% | 68.8% | 28.1% | 25.0% |
| stale_events | 31 | 74.2% | 74.2% | 74.2% | 74.2% | 0.0% |
| reordered_events | 34 | 70.6% | 70.6% | 70.6% | 70.6% | 0.0% |
| parser_corruption | 31 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| conflicting_evidence | 30 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% |
| context_flood | 29 | 96.6% | 0.0% | 0.0% | 0.0% | 0.0% |
| false_edges_weak | 29 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| forgery_strong | 25 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| joint_fabricate_edges | 27 | 100.0% | 100.0% | 66.7% | 3.7% | 0.0% |
| joint_conceal_deletion | 30 | 83.3% | 66.7% | 66.7% | 36.7% | 10.0% |
| joint_conceal_flood | 31 | 100.0% | 22.6% | 22.6% | 22.6% | 0.0% |

## Ablations (delta vs D_full)

| Config | Unsafe (attacked) [95% CI] | log | graph | joint | Ideal outcome (attacked) | Burden (clean) | False action | Missed incident | Verify ms | Prompt tok |
|---|---|---|---|---|---|---|---|---|---|---|
| D_full | 7.4% [5.4%, 10.1%] | 0.0% | 13.7% | 3.4% | 82.9% | 16.5% | 12.1% | 3.1% | 1.59 | 1254 |
| D-no_order | 12.4% [9.8%, 15.6%] (+5.0 pp) | 0.0% | 23.7% | 3.4% | 77.9% | 16.5% | 12.1% | 3.1% | 1.45 | 1254 |
| D-no_freshness | 12.2% [9.6%, 15.4%] (+4.8 pp) | 0.0% | 23.2% | 3.4% | 78.1% | 16.5% | 12.1% | 3.1% | 1.44 | 1254 |
| D-no_integrity | 13.8% [11.0%, 17.2%] (+6.4 pp) | 0.0% | 26.1% | 4.5% | 76.4% | 16.5% | 12.6% | 3.1% | 1.41 | 1254 |
| D-no_confidence | 23.6% [20.0%, 27.5%] (+16.1 pp) | 0.0% | 38.6% | 23.9% | 66.7% | 16.5% | 35.0% | 3.1% | 1.41 | 1254 |
| D-no_three_state | 34.3% [30.2%, 38.6%] (+26.9 pp) | 0.0% | 63.9% | 13.6% | 48.6% | 10.1% | 12.1% | 39.5% | 1.56 | 1254 |
| D-no_gate | 14.5% [11.6%, 17.9%] (+7.0 pp) | 11.6% | 14.1% | 20.5% | 81.0% | 16.5% | 12.1% | 12.6% | 0.05 | 1254 |
| D-no_selector | 7.6% [5.6%, 10.4%] (+0.2 pp) | 0.0% | 14.1% | 3.4% | 71.7% | 16.5% | 12.1% | 3.4% | 1.50 | 2777 |
| D-no_hardening | 7.4% [5.4%, 10.1%] (+0.0 pp) | 0.0% | 13.7% | 3.4% | 68.4% | 16.5% | 12.1% | 3.1% | 1.46 | 1151 |

## Paired tests on attacked cases

| A vs B | cases unsafe only in A | unsafe only in B | exact p |
|---|---|---|---|
| A_raw vs D_full | 356 | 0 | 1.4e-107 |
| B_hardened vs D_full | 240 | 0 | 1.1e-72 |
| C_graph_binary vs D_full | 211 | 0 | 6.1e-64 |
| E_abstain_only vs D_full | 112 | 0 | 3.9e-34 |

