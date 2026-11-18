# Results

> **Simulated LLM.** These numbers come from a seeded stand-in for an 8B model whose fault rates are assumptions (see `SimProfile`). They validate the pipeline and harness, not Llama.

Test cases: 139 (calibration: 61); tau=0.7 chosen on calibration only.

## Main comparison

| Config | Unsafe (attacked) [95% CI] | log | graph | joint | Ideal outcome (attacked) | Burden (clean) | False action | Missed incident | Verify ms | Prompt tok |
|---|---|---|---|---|---|---|---|---|---|---|
| A_raw | 79.0% [70.8%, 85.3%] | 60.0% | 85.5% | 90.9% | 21.0% | 15.0% | 55.8% | 41.4% | 0.00 | 2905 |
| B_hardened | 52.1% [43.2%, 60.9%] (-26.9 pp) | 20.0% | 71.0% | 50.0% | 47.1% | 15.0% | 44.2% | 6.9% | 0.00 | 1275 |
| C_graph_binary | 47.9% [39.1%, 56.8%] (-31.1 pp) | 8.6% | 71.0% | 45.5% | 50.4% | 15.0% | 34.6% | 13.8% | 0.03 | 1275 |
| E_abstain_only | 27.7% [20.5%, 36.4%] (-51.3 pp) | 8.6% | 45.2% | 9.1% | 68.1% | 15.0% | 13.5% | 6.9% | 0.03 | 1275 |
| D_full | 6.7% [3.4%, 12.7%] (-72.3 pp) | 0.0% | 12.9% | 0.0% | 85.7% | 15.0% | 13.5% | 1.1% | 1.38 | 1275 |

## Per-family unsafe rate

| Family | n | A_raw | B_hardened | C_graph_binary | E_abstain_only | D_full |
|---|---|---|---|---|---|---|
| clean_incident | 5 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| clean_benign | 6 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_hardneg | 9 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| inject_conceal_atomic | 4 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| inject_conceal_stitched | 8 | 62.5% | 25.0% | 25.0% | 25.0% | 0.0% |
| inject_conceal_obfuscated | 5 | 40.0% | 20.0% | 20.0% | 20.0% | 0.0% |
| inject_fabricate_atomic | 6 | 50.0% | 50.0% | 0.0% | 0.0% | 0.0% |
| inject_fabricate_stitched | 6 | 83.3% | 16.7% | 0.0% | 0.0% | 0.0% |
| inject_fabricate_obfuscated | 6 | 33.3% | 0.0% | 0.0% | 0.0% | 0.0% |
| edge_deletion | 6 | 50.0% | 50.0% | 50.0% | 16.7% | 16.7% |
| stale_events | 8 | 37.5% | 37.5% | 37.5% | 37.5% | 0.0% |
| reordered_events | 9 | 88.9% | 88.9% | 88.9% | 88.9% | 0.0% |
| parser_corruption | 7 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| conflicting_evidence | 9 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% |
| context_flood | 9 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| false_edges_weak | 7 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| forgery_strong | 7 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| joint_fabricate_edges | 5 | 100.0% | 100.0% | 80.0% | 0.0% | 0.0% |
| joint_conceal_deletion | 8 | 75.0% | 62.5% | 62.5% | 12.5% | 0.0% |
| joint_conceal_flood | 9 | 100.0% | 11.1% | 11.1% | 11.1% | 0.0% |

## Ablations (delta vs D_full)

| Config | Unsafe (attacked) [95% CI] | log | graph | joint | Ideal outcome (attacked) | Burden (clean) | False action | Missed incident | Verify ms | Prompt tok |
|---|---|---|---|---|---|---|---|---|---|---|
| D_full | 6.7% [3.4%, 12.7%] | 0.0% | 12.9% | 0.0% | 85.7% | 15.0% | 13.5% | 1.1% | 1.38 | 1275 |
| D-no_order | 13.4% [8.4%, 20.7%] (+6.7 pp) | 0.0% | 25.8% | 0.0% | 79.0% | 15.0% | 13.5% | 1.1% | 1.33 | 1275 |
| D-no_freshness | 9.2% [5.2%, 15.8%] (+2.5 pp) | 0.0% | 17.7% | 0.0% | 83.2% | 15.0% | 13.5% | 1.1% | 1.25 | 1275 |
| D-no_integrity | 14.3% [9.1%, 21.7%] (+7.6 pp) | 0.0% | 27.4% | 0.0% | 78.2% | 15.0% | 13.5% | 1.1% | 1.24 | 1275 |
| D-no_confidence | 21.8% [15.4%, 30.1%] (+15.1 pp) | 0.0% | 35.5% | 18.2% | 70.6% | 15.0% | 34.6% | 1.1% | 1.21 | 1275 |
| D-no_three_state | 34.5% [26.5%, 43.4%] (+27.7 pp) | 0.0% | 59.7% | 18.2% | 51.3% | 15.0% | 13.5% | 39.1% | 1.36 | 1275 |
| D-no_gate | 10.9% [6.5%, 17.8%] (+4.2 pp) | 8.6% | 12.9% | 9.1% | 84.9% | 15.0% | 13.5% | 6.9% | 0.04 | 1275 |
| D-no_selector | 6.7% [3.4%, 12.7%] (+0.0 pp) | 0.0% | 12.9% | 0.0% | 71.4% | 15.0% | 13.5% | 1.1% | 1.35 | 3008 |
| D-no_hardening | 6.7% [3.4%, 12.7%] (+0.0 pp) | 0.0% | 12.9% | 0.0% | 71.4% | 15.0% | 13.5% | 1.1% | 1.35 | 1172 |

## Paired tests on attacked cases

| A vs B | cases unsafe only in A | unsafe only in B | exact p |
|---|---|---|---|
| A_raw vs D_full | 86 | 0 | 2.6e-26 |
| B_hardened vs D_full | 54 | 0 | 1.1e-16 |
| C_graph_binary vs D_full | 49 | 0 | 3.6e-15 |
| E_abstain_only vs D_full | 25 | 0 | 6e-08 |

