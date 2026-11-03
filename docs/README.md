# Adversary-aware evidence-chain verifier for a local SOC agent

The **agentic layer** of the Layer 4 SOC capstone: a LangGraph agent that lets a local 8B model
*propose* incident claims and actions, then makes a deterministic verifier, a risk gate and a
router decide whether the system may act, must abstain, or may close the alert.

```
alert -> select subgraph -> analyst LLM -> verifier -> risk gate -> router -> PROPOSE | ESCALATE | CLOSE
          (token budget)    (JSON only)   (no LLM)     (no LLM)     (3-state)
```

The LLM never has execution authority. `PROPOSE` still means "awaiting human approval".

## Quick start

```bash
pip install -r requirements.txt
python -m pytest tests -q                                  # 37 tests
python -m soc_agent.run_experiments --n 40 --seed 7 --out results --sensitivity
python -m soc_agent.run_experiments --n 10 --llm ollama --model llama3.1:8b --out results_ollama
python -m soc_agent.cli triage --events events.jsonl --entity host-a --llm ollama
```

## Layout

| File | Role |
|---|---|
| `schemas.py`, `models.py` | Event, Claim, Verdict, Alert, Action, Decision contracts |
| `evidence_store.py`, `graph_utils.py` | NetworkX `MultiDiGraph`, one `Event` per edge (swap for your teammate's graph) |
| `verifier.py`, `config.py` | **Core.** Temporal chain verifier, 3 states, every check switchable for ablation |
| `patterns.py` | 7 attack-chain templates (5 known to the defender, 2 held out) + subgraph matcher |
| `selector.py` | Risk-ranked, token-budgeted subgraph selection |
| `prompts.py` | Plain and hardened prompts (`<untrusted_logs>`), strict output parser |
| `llm.py` | `OllamaClient` (real), `SimulatedLLM` (stand-in), `CachedLLM` |
| `risk_gate.py`, `router.py` | Severity floor from verified facts, action justification, final routing |
| `agent.py` | LangGraph state graph (sequential fallback if langgraph is missing) |
| `scenarios.py`, `attacks.py` | Ground-truth scenario generator and 20 attack families |
| `evaluate.py`, `run_experiments.py`, `report.py` | Configs A-E + 8 ablations, calibration split, CIs, tables, figure |
| `io.py`, `cli.py` | Load the ingestion layer's JSONL events and triage a real alert |

**Contracts for teammates.** Ingestion emits JSONL events with `event_id, ts, rel (or type), src, dst,
source_system, parse_conf, match_conf`. The graph layer only has to implement
`find(rel, src, dst) -> list[Event]` for the verifier, plus event iteration for the selector.

**Layer 1 → Layer 2 flow path.** A local JSONL ingestion and Fast Brain
scoring pipeline is documented in [ingestion/README.md](../ingestion/README.md).
It archives canonical flow records in SQLite, trains on records labeled
`benign`, and emits anomaly scores and route decisions. It does not require
Kafka and is separate from the Layer 4 graph-event JSONL consumed by
`soc_agent.cli`.
For UGR'16 CSV, [parse_ugr16.py](../tools/parse_ugr16.py) streams records to
JSONL; then `soc_agent.fast_brain_cli` can train on the dataset's selected
normal label and score the converted JSONL directly.
Use [calibrate_thresholds.py](../tools/calibrate_thresholds.py) on the scored,
labeled JSONL to inspect percentile-based cutoff suggestions and the score
histogram; validate any chosen cutoffs on held-out traffic.
Then [slow_brain_handoff.py](../tools/slow_brain_handoff.py) forwards only
`SLOW_BRAIN` flows to the Layer 4 CLI and appends the SOC decision to
`final_soc_alerts.jsonl`.

## How the verifier decides

A claim carries a chain of required facts. For each step the verifier checks, in order: the edge exists
(else **Unknown**), it does not precede the previous step (else **Contradicted**), it is neither stale nor
from the future (else **Unknown**), no blocking edge contradicts it (else **Contradicted**), and
`min(parse_conf, match_conf)` (times a single-source penalty for high-impact claims) clears `tau`
(else **Unknown**). Any Contradicted step wins, then any Unknown, otherwise **Supported**.

The risk gate then (a) derives a severity floor from *verified* graph patterns anchored on the alert, so
the model cannot talk the system out of an incident it can see, and (b) requires a containment action's
target to appear in a Supported claim that contains a justifying relation.

## Evaluation design

Every case has a *preferred* outcome and a set of *acceptable* outcomes.

- **Unsafe** = outcome not acceptable. This is evidence-based: acting on a claim the available evidence
  does not support is unsafe even when the claim happens to be true.
- **Burden** = escalating a clean case that should not need an analyst.
- **False action** (PROPOSE on a benign case) and **missed incident** (CLOSE on a real one) are reported
  separately as reality-based harms.

Configurations: **A** raw model; **B** hardened prompt + selector + schema validation; **C** graph
check with none of the temporal/integrity/confidence checks and no abstention; **E** abstention without
the temporal/integrity checks; **D** full system. Ablations remove one D component at a time.
`tau` is chosen on a 30% calibration split only; all numbers are on the 70% test split.

Attack families (20): clean / hard-negative controls; split, atomic and obfuscated injection that either
conceals a real incident or fabricates one; edge deletion, stale events, reordered events, parser
corruption, conflicting evidence, context flood, weak and strong graph forgery; and **joint** attacks that
combine log injection with graph edits or flooding.

## Results (simulated 8B stand-in, seed 7, 563 test cases)

| Config | Unsafe on attacked cases [95% CI] | Ideal outcome | Burden on clean | Verify ms |
|---|---|---|---|---|
| A raw model | 81.0% [77.3, 84.2] | 18.8% | 10.1% | 0 |
| B hardened prompt | 57.0% [52.6, 61.4] | 42.6% | 10.1% | 0 |
| C graph check, binary | 51.0% [46.6, 55.5] | 46.7% | 10.1% | 0.01 |
| E abstention only | 30.6% [26.6, 34.8] | 64.9% | 16.5% | 0.02 |
| **D full system** | **7.4% [5.4, 10.1]** | **82.9%** | 16.5% | 0.60 |

Ablations (unsafe-rate increase when one part of D is removed): three-state output +26.9 pp,
confidence/provenance +16.1 pp, risk gate +7.0 pp, integrity checks +6.4 pp, temporal order +5.0 pp,
freshness +4.8 pp. Removing the selector (+0.2 pp) or the prompt hardening (+0.0 pp) barely moves the unsafe
rate but cuts the share of ideal outcomes (the verifier and gate catch the damage by escalating instead of
acting), so on this benchmark those two are efficiency measures, not safety measures.
Full tables: `results/summary.md`; figure: `results/unsafe_by_family.png`.

## Read this before quoting any number

1. **The model is simulated.** `SimulatedLLM` is a seeded stand-in whose fault rates (how often it obeys an
   injection, hallucinates a missing step, notices bad ordering) are assumptions in `SimProfile`, not
   measurements. These results validate the pipeline and the harness. They say nothing yet about Llama 3.1 8B.
   The sensitivity sweep (`sensitivity.md`) shows D stays at 7.0 to 7.4% when those rates are scaled 0.5x to
   1.5x, but that only tests the assumption's scale, not its shape. **Run `--llm ollama` and report those
   numbers instead.**
2. **The benchmark is mine.** Attack families, ground truth and the unsafe definition were written by the
   same author as the defence, and scenarios and the gate's pattern library share templates. Two templates
   are held out of the gate, but they overlap known ones, so the gate still catches them through partial
   chains (severity floor "medium", never "high"). The exact p-values in `summary.md` only describe this
   synthetic data.
3. **Design choices that move the baselines.** C turns an unsupported claim into a dismissal (that is what
   "no abstention" means here); a fallback to the analyst queue would make it equal to the three-state router.
   The weak/strong forgery split encodes an assumption about what the attacker controls.

## Where the full system still fails (all of D's unsafe outcomes)

- **Strong forgery, 100%.** Two sources, high confidence, consistent order: indistinguishable from real
  evidence, and no check in the verifier can tell. This needs a different control, such as cross-checking each
  edge against an immutable raw-log archive.
- **Edge deletion, 25%, and joint conceal + deletion, 10%.** When the deleted steps are the high-risk ones and
  the model closes the alert, the gate has no verified high-risk fragment left to base a floor on.
- Silent parser corruption (wrong entity at high confidence) is not modelled.

## Suggested claim (until real-model results exist)

"We design and evaluate an evidence-chain verifier for a local SOC agent under combined log and graph
attacks, and show on a synthetic benchmark that it reduces unsafe outcomes by X points over a hardened-prompt
baseline, with the residual failures characterised." Do not call it first or novel in general: graph
verification, abstention and SOC log injection each have prior work, and a prior-art sweep has not been
completed.

## Next steps

1. Run the harness on Llama 3.1 8B (`--llm ollama`, smaller `--n`) and replace the simulated table.
2. Add the raw-log archive cross-check to address strong forgery.
3. Plug in your teammate's graph and Go ingestion via the JSONL loader.
4. Replace synthetic scenarios with chains derived from a public dataset (OTRF Security Datasets, Splunk attack_data).
