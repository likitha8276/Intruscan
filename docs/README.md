# Adversary-aware evidence-chain verifier for a local SOC agent

The **agentic layer** of the Layer 4 SOC capstone: a LangGraph agent that lets a Groq-hosted LLM

*propose* incident claims and actions, then makes a deterministic verifier, a risk gate and a

router decide whether the system may act, must abstain, or may close the alert.

```

alert -> select subgraph -> analyst LLM -> verifier -> risk gate -> router -> PROPOSE | ESCALATE | CLOSE

          (token budget)    (JSON only)   (no LLM)     (no LLM)     (3-state)

```

The LLM never has execution authority. `PROPOSE` still means "awaiting human approval".

For live analysis, --llm auto tries Groq first and falls back to Gemini only for transient provider failures (rate limits, server errors, timeouts, or connection failures). Authentication, configuration, and malformed-response errors do not trigger fallback.
Set both GROQ_API_KEY and GEMINI_API_KEY in the repository-root .env file. GEMINI_MODEL is configurable; the default is gemini-3.8-flash. Never commit .env or share API keys.
Use --llm groq or --llm gemini to select one provider, and --llm sim for reproducible simulated experiments.

## Quick start

```bash

pip install -r requirements.txt

python -m pytest tests -q                                  # 67 tests

python -m soc_agent.run_experiments --n 40 --seed 7 --out results --sensitivity

python -m soc_agent.run_experiments --n 10 --llm auto --model openai/gpt-oss-20b --out results_auto

python -m soc_agent.cli triage --events events.jsonl --entity host-a --llm auto

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

| `llm.py` | `GroqClient`, `GeminiClient`, transient-error `FallbackLLM`, `SimulatedLLM`, `CachedLLM` |

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

`benign`, and emits anomaly scores and route decisions. It uses neither

Kafka nor PCAP capture (input is local JSONL files) and is separate from the Layer 4 graph-event JSONL consumed by

`soc_agent.cli`.

For UGR'16 CSV, [parse_ugr16.py](../tools/parse_ugr16.py) streams records to

JSONL; then `soc_agent.fast_brain_cli` can train on the dataset's selected

normal label and score the converted JSONL directly.

Use [calibrate_thresholds.py](../tools/calibrate_thresholds.py) on the scored,

labeled JSONL to inspect percentile-based cutoff suggestions and the score

histogram; validate any chosen cutoffs on held-out traffic. For a model-bound
workflow (candidate thresholds, independent test evaluation, explicit approval)
see the "Routing thresholds" section of [ingestion/README.md](../ingestion/README.md).

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

4. Replace synthetic scenarios with chains derived from a public dataset (OTRF Security Datasets, Splunk attack_data).
