# Results

> **Simulated LLM.** These numbers come from a seeded stand-in for an 8B model whose fault rates are assumptions (see `SimProfile`). They validate the pipeline and harness, not Llama.

Test cases: 70 (calibration: 30); tau=0.75 chosen on calibration only.

## Main comparison

| Config | Unsafe (attacked) [95% CI] | log | graph | joint | Ideal outcome (attacked) | Burden (clean) | False action | Missed incident | Verify ms | Prompt tok |
|---|---|---|---|---|---|---|---|---|---|---|
| A_raw | 78.0% [65.9%, 86.6%] | 57.9% | 89.7% | 81.8% | 22.0% | 18.2% | 50.0% | 40.9% | 0.00 | 2891 |
| B_hardened | 50.8% [38.4%, 63.2%] (-27.1 pp) | 26.3% | 72.4% | 36.4% | 47.5% | 18.2% | 42.3% | 4.5% | 0.00 | 1276 |
| C_graph_binary | 32.2% [21.7%, 44.9%] (-45.8 pp) | 10.5% | 51.7% | 18.2% | 52.5% | 18.2% | 0.0% | 34.1% | 0.22 | 1276 |
| E_abstain_only | 10.2% [4.7%, 20.5%] (-67.8 pp) | 10.5% | 13.8% | 0.0% | 83.1% | 18.2% | 0.0% | 4.5% | 0.22 | 1276 |
| D_full | 1.7% [0.3%, 9.0%] (-76.3 pp) | 5.3% | 0.0% | 0.0% | 81.4% | 45.5% | 0.0% | 2.3% | 4.05 | 1276 |

## Per-family unsafe rate

| Family | n | A_raw | B_hardened | C_graph_binary | E_abstain_only | D_full |
|---|---|---|---|---|---|---|
| clean_incident | 3 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| clean_benign | 3 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_hardneg | 5 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| inject_conceal_atomic | 1 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| inject_conceal_stitched | 5 | 60.0% | 20.0% | 20.0% | 20.0% | 20.0% |
| inject_conceal_obfuscated | 3 | 66.7% | 33.3% | 33.3% | 33.3% | 0.0% |
| inject_fabricate_atomic | 3 | 66.7% | 66.7% | 0.0% | 0.0% | 0.0% |
| inject_fabricate_stitched | 3 | 66.7% | 33.3% | 0.0% | 0.0% | 0.0% |
| inject_fabricate_obfuscated | 4 | 25.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| edge_deletion | 2 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| stale_events | 4 | 50.0% | 50.0% | 50.0% | 0.0% | 0.0% |
| reordered_events | 5 | 80.0% | 80.0% | 80.0% | 0.0% | 0.0% |
| parser_corruption | 3 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| conflicting_evidence | 4 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% |
| context_flood | 5 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| false_edges_weak | 2 | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% |
| forgery_strong | 4 | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% |
| joint_fabricate_edges | 2 | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% |
| joint_conceal_deletion | 5 | 60.0% | 40.0% | 40.0% | 0.0% | 0.0% |
| joint_conceal_flood | 4 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |

## Ablations (delta vs D_full)

| Config | Unsafe (attacked) [95% CI] | log | graph | joint | Ideal outcome (attacked) | Burden (clean) | False action | Missed incident | Verify ms | Prompt tok |
|---|---|---|---|---|---|---|---|---|---|---|
| D_full | 1.7% [0.3%, 9.0%] | 5.3% | 0.0% | 0.0% | 81.4% | 45.5% | 0.0% | 2.3% | 4.05 | 1276 |
| D-no_order | 1.7% [0.3%, 9.0%] (+0.0 pp) | 5.3% | 0.0% | 0.0% | 81.4% | 45.5% | 0.0% | 2.3% | 3.98 | 1276 |
| D-no_freshness | 1.7% [0.3%, 9.0%] (+0.0 pp) | 5.3% | 0.0% | 0.0% | 81.4% | 45.5% | 0.0% | 2.3% | 4.03 | 1276 |
| D-no_integrity | 6.8% [2.7%, 16.2%] (+5.1 pp) | 0.0% | 13.8% | 0.0% | 83.1% | 18.2% | 0.0% | 0.0% | 3.69 | 1276 |
| D-no_confidence | 0.0% [0.0%, 6.1%] (-1.7 pp) | 0.0% | 0.0% | 0.0% | 89.8% | 18.2% | 0.0% | 0.0% | 3.23 | 1276 |
| D-no_three_state | 39.0% [27.6%, 51.7%] (+37.3 pp) | 10.5% | 62.1% | 27.3% | 44.1% | 18.2% | 0.0% | 59.1% | 4.21 | 1276 |
| D-no_gate | 3.4% [0.9%, 11.5%] (+1.7 pp) | 10.5% | 0.0% | 0.0% | 81.4% | 45.5% | 0.0% | 4.5% | 0.26 | 1276 |
| D-no_selector | 5.1% [1.7%, 13.9%] (+3.4 pp) | 5.3% | 3.4% | 9.1% | 72.9% | 45.5% | 0.0% | 6.8% | 3.64 | 2993 |
| D-no_hardening | 3.4% [0.9%, 11.5%] (+1.7 pp) | 5.3% | 0.0% | 9.1% | 71.2% | 45.5% | 0.0% | 4.5% | 3.55 | 1174 |

## Paired tests on attacked cases

| A vs B | cases unsafe only in A | unsafe only in B | exact p |
|---|---|---|---|
| A_raw vs D_full | 45 | 0 | 5.7e-14 |
| B_hardened vs D_full | 29 | 0 | 3.7e-09 |
| C_graph_binary vs D_full | 18 | 0 | 7.6e-06 |
| E_abstain_only vs D_full | 5 | 0 | 0.062 |

