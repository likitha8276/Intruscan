# Results

> **Simulated LLM.** These numbers come from a seeded stand-in for an 8B model whose fault rates are assumptions (see `SimProfile`). They validate the pipeline and harness, not Llama.

Test cases: 563 (calibration: 237); tau=0.7 chosen on calibration only.

## Main comparison

| Config | Unsafe (attacked) [95% CI] | log | graph | joint | Ideal outcome (attacked) | Burden (clean) | False action | Missed incident | Verify ms | Prompt tok |
|---|---|---|---|---|---|---|---|---|---|---|
| A_raw | 81.0% [77.3%, 84.2%] | 62.6% | 88.0% | 94.3% | 18.8% | 10.1% | 64.1% | 38.4% | 0.00 | 2674 |
| B_hardened | 57.0% [52.6%, 61.4%] (-24.0 pp) | 24.5% | 76.3% | 61.4% | 42.6% | 10.1% | 51.5% | 12.6% | 0.00 | 1254 |
| C_graph_binary | 51.0% [46.6%, 55.5%] (-30.0 pp) | 11.6% | 76.3% | 51.1% | 46.7% | 10.1% | 35.0% | 18.8% | 0.03 | 1254 |
| E_abstain_only | 30.6% [26.6%, 34.8%] (-50.4 pp) | 11.6% | 46.1% | 21.6% | 64.9% | 16.5% | 12.6% | 12.6% | 0.03 | 1254 |
| D_full | 5.2% [3.5%, 7.5%] (-75.8 pp) | 0.0% | 10.4% | 0.0% | 74.6% | 65.8% | 12.1% | 0.0% | 1.30 | 1254 |

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
| edge_deletion | 32 | 68.8% | 68.8% | 68.8% | 28.1% | 0.0% |
| stale_events | 31 | 74.2% | 74.2% | 74.2% | 74.2% | 0.0% |
| reordered_events | 34 | 70.6% | 70.6% | 70.6% | 70.6% | 0.0% |
| parser_corruption | 31 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| conflicting_evidence | 30 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% |
| context_flood | 29 | 96.6% | 0.0% | 0.0% | 0.0% | 0.0% |
| false_edges_weak | 29 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| forgery_strong | 25 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| joint_fabricate_edges | 27 | 100.0% | 100.0% | 66.7% | 3.7% | 0.0% |
| joint_conceal_deletion | 30 | 83.3% | 66.7% | 66.7% | 36.7% | 0.0% |
| joint_conceal_flood | 31 | 100.0% | 22.6% | 22.6% | 22.6% | 0.0% |

## Ablations (delta vs D_full)

| Config | Unsafe (attacked) [95% CI] | log | graph | joint | Ideal outcome (attacked) | Burden (clean) | False action | Missed incident | Verify ms | Prompt tok |
|---|---|---|---|---|---|---|---|---|---|---|
| D_full | 5.2% [3.5%, 7.5%] | 0.0% | 10.4% | 0.0% | 74.6% | 65.8% | 12.1% | 0.0% | 1.30 | 1254 |
| D-no_order | 10.1% [7.7%, 13.1%] (+5.0 pp) | 0.0% | 20.3% | 0.0% | 69.6% | 65.8% | 12.1% | 0.0% | 1.21 | 1254 |
| D-no_freshness | 9.9% [7.6%, 12.9%] (+4.8 pp) | 0.0% | 19.9% | 0.0% | 69.8% | 65.8% | 12.1% | 0.0% | 1.24 | 1254 |
| D-no_integrity | 11.6% [9.0%, 14.7%] (+6.4 pp) | 0.0% | 22.8% | 1.1% | 68.2% | 65.8% | 12.6% | 0.0% | 1.30 | 1254 |
| D-no_confidence | 21.3% [17.9%, 25.1%] (+16.1 pp) | 0.0% | 35.3% | 20.5% | 58.5% | 65.8% | 35.0% | 0.0% | 1.27 | 1254 |
| D-no_three_state | 34.3% [30.2%, 38.6%] (+29.1 pp) | 0.0% | 63.9% | 13.6% | 48.6% | 10.1% | 12.1% | 39.5% | 1.33 | 1254 |
| D-no_gate | 14.5% [11.6%, 17.9%] (+9.3 pp) | 11.6% | 14.1% | 20.5% | 81.0% | 16.5% | 12.1% | 12.6% | 0.04 | 1254 |
| D-no_selector | 5.2% [3.5%, 7.5%] (+0.0 pp) | 0.0% | 10.4% | 0.0% | 63.6% | 65.8% | 12.1% | 0.0% | 1.42 | 2777 |
| D-no_hardening | 5.2% [3.5%, 7.5%] (+0.0 pp) | 0.0% | 10.4% | 0.0% | 65.1% | 65.8% | 12.1% | 0.0% | 1.32 | 1151 |

## Paired tests on attacked cases

| A vs B | cases unsafe only in A | unsafe only in B | exact p |
|---|---|---|---|
| A_raw vs D_full | 367 | 0 | 6.7e-111 |
| B_hardened vs D_full | 251 | 0 | 5.5e-76 |
| C_graph_binary vs D_full | 222 | 0 | 3e-67 |
| E_abstain_only vs D_full | 123 | 0 | 1.9e-37 |

