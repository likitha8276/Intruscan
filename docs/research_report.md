# Robust SOC Agent via Temporal Evidence Chains and Risk-Aware Knowledge-Graph Verification

## Abstract

Security Operations Center (SOC) agents can help analysts investigate alerts by interpreting logs, correlating events, and proposing incident-response actions. However, language-model-based agents may accept injected instructions, rely on fabricated evidence, overlook temporal inconsistencies, or recommend actions unsupported by available evidence.

This project presents an adversary-aware evidence-chain verification framework for a local SOC agent. The architecture combines an analyst language model with deterministic temporal evidence-chain verification, three-state claim assessment, risk-aware decision gating, and final action routing. The language model proposes claims and actions but does not directly execute them. The extended implementation also introduces HMAC-based event provenance verification to assess whether evidence has been signed and remains unmodified.

Evaluation uses a synthetic benchmark containing clean controls and adversarial scenarios involving injection, graph manipulation, temporal inconsistency, parser corruption, conflicting evidence, and combined attacks. In the original simulated-LLM experiment, the full system reduced the unsafe-outcome rate from 81.0% for the raw model to 7.4%. In a later 70-test-case experiment, the full system recorded 8.5% unsafe outcomes on attacked cases. A separate provenance comparison recorded 5 unsafe cases among 59 attacked cases for the full system and 1 among 59 for the provenance-enabled configuration.

These results demonstrate the behavior of the implemented pipeline on its synthetic benchmark. They do not establish performance on a real language model or a production SOC environment. The results also reveal a substantial clean-case escalation burden and residual failures that require further investigation.

**Keywords:** Security Operations Center, evidence-chain verification, provenance, knowledge graphs, risk-aware decision making, language-model security, abstention.

## 1. Introduction

SOC analysts must determine whether alerts represent genuine security incidents, reconstruct event sequences, assess the reliability of evidence, and select appropriate responses. Language models can assist with these tasks, but their outputs may be influenced by untrusted log content or may describe chains of events that the underlying evidence does not support.

A reliable agent therefore needs to distinguish between generating a plausible explanation and verifying that explanation against available evidence.

This project addresses that problem by separating probabilistic analysis from deterministic verification and action authorization. The analyst model proposes incident claims and actions. A verifier checks the claims against graph evidence, while a risk gate and router determine whether the proposed outcome is acceptable.

### 1.1 Problem statement

How can a local SOC agent reduce unsupported or unsafe incident-response decisions when logs and evidence graphs may be incomplete, inconsistent, stale, manipulated, or adversarially influenced?

### 1.2 Objectives

1. Verify claimed attack chains against graph evidence.
2. Check temporal order, evidence freshness, integrity, and confidence.
3. Represent uncertainty explicitly instead of treating every claim as true or false.
4. Prevent containment actions that lack verified supporting evidence.
5. Evaluate the contributions of individual safeguards through ablation experiments.
6. Investigate whether authenticated event provenance improves resistance to forged evidence.

### 1.3 Contributions

The implemented system combines:

- Temporal evidence-chain verification with three possible verdicts: Supported, Contradicted, and Unknown.
- A deterministic risk gate that derives a severity floor from verified evidence and checks whether proposed containment actions are justified.
- Three-state routing among PROPOSE, ESCALATE, and CLOSE.
- A configurable evaluation harness with synthetic attack families, baseline configurations, and component ablations.
- An HMAC-based provenance extension and a comparative experiment examining its effect on unsafe outcomes.

These contributions describe the implemented system. Their novelty relative to prior research requires a separate literature review.

## 2. System Architecture

The processing pipeline is:

**Alert → Subgraph selection → Analyst model → Evidence verifier → Risk gate → Router → Final decision**

### 2.1 Subgraph selection

The selector chooses a relevant portion of the event graph under a token budget. This limits the evidence supplied to the analyst model and helps control prompt size.

### 2.2 Analyst model

The model proposes incident claims, severity, and an action in a structured JSON format. The implementation supports both an Ollama client and a simulated LLM used for controlled experiments.

The model is not granted direct execution authority. PROPOSE indicates a proposed response awaiting human approval.

### 2.3 Evidence-chain verifier

Each claim contains a chain of required facts. The verifier checks the corresponding events and their consistency.

The documented verification process checks:

1. Whether the required event exists.
2. Whether events respect temporal ordering.
3. Whether evidence is stale or from the future.
4. Whether blocking evidence contradicts the claim.
5. Whether event parsing and matching confidence meet the configured threshold, including a single-source penalty for high-impact claims.

The verifier returns Supported, Contradicted, or Unknown. Contradicted evidence takes precedence over Unknown, and Unknown takes precedence over Supported.

### 2.4 Risk gate

The risk gate derives a severity floor from verified graph patterns anchored on the alert. It also checks whether a proposed containment target appears in a Supported claim containing a relation that justifies the action.

The extended implementation adds a corroborated high-risk event fallback that requires valid provenance signatures and corroborating events from multiple source systems. This fallback must be evaluated carefully because multiple signed events do not automatically establish that they form a coherent attack chain.

### 2.5 Decision router

The router selects among three outcomes:

- **PROPOSE:** a proposed response awaits human approval.
- **ESCALATE:** the case requires analyst review.
- **CLOSE:** the alert is closed.

This design separates model-generated recommendations from deterministic verification and final routing.

## 3. Provenance Verification

The provenance extension uses HMAC-SHA256 signatures over a canonical representation of event fields, including the event identifier, timestamp, relation, source, destination, source system, and confidence metadata.

During verification, the signature is recomputed and compared with the event's recorded signature. If a signed field is modified, the signature should no longer validate.

The provenance-enabled configuration requires a verification key and filters candidate evidence to events with valid signatures.

The benchmark uses a fixed synthetic signing key. This is appropriate for testing the mechanism but is not production key management. A deployed system would require secure key storage, controlled key rotation, trusted ingestion boundaries, and protection against compromised signing infrastructure.

A valid signature establishes integrity relative to the signing key; it does not independently establish that an event is truthful. If an attacker can cause a compromised ingestion system to sign fabricated data, provenance verification alone cannot prevent the fabrication.

## 4. Experimental Methodology

### 4.1 Benchmark design

The benchmark generates synthetic scenarios containing clean controls and adversarial cases. The documented attack families include:

- Log injection that conceals or fabricates incidents.
- Atomic, stitched, and obfuscated attacks.
- Event deletion and stale events.
- Reordered events and parser corruption.
- Conflicting evidence and context flooding.
- Weak and strong graph forgery.
- Joint attacks combining log injection with graph manipulation or flooding.

The benchmark's ground truth and the defense's pattern library are developed within the same project. This creates a risk of benchmark-specific bias and must be considered when interpreting results.

### 4.2 Metrics

The evaluation reports several distinct outcomes:

- **Unsafe outcome rate:** the proportion of attacked cases whose decisions fall outside the benchmark's acceptable outcomes.
- **Ideal outcome rate:** the proportion of attacked cases receiving an ideal decision.
- **Clean-case burden:** the proportion of clean cases unnecessarily escalated.
- **False action:** a proposed action on a benign case.
- **Missed incident:** closing a real incident that requires investigation.
- **Verification latency:** measured time spent verifying evidence.
- **Prompt tokens:** model input-token usage.

These metrics measure different aspects of performance and should not be treated as interchangeable.

### 4.3 Configurations

The documented comparisons include:

- A_raw: raw analyst model.
- B_hardened: hardened prompting, selector, and schema validation.
- C_graph_binary: graph checking without the full temporal, integrity, confidence, and abstention safeguards.
- E_abstain_only: abstention without the full verification checks.
- D_full: full verification and risk-gating pipeline.
- F_provenance: provenance-enabled configuration.
- Additional ablations removing individual components.

The threshold is selected using a calibration split rather than the test split. The original README describes a 30% calibration split and a 70% test split.

## 5. Results

### 5.1 Original experiment

The README records an original simulated-LLM experiment with 563 test cases and seed 7.

| Configuration | Unsafe rate on attacked cases | Ideal outcome rate | Clean-case burden |
|---|---:|---:|---:|
| A_raw | 81.0% | 18.8% | 10.1% |
| B_hardened | 57.0% | 42.6% | 10.1% |
| C_graph_binary | 51.0% | 46.7% | 10.1% |
| E_abstain_only | 30.6% | 64.9% | 16.5% |
| D_full | 7.4% | 82.9% | 16.5% |

In this experiment, D_full reduced the unsafe-outcome rate by 73.6 percentage points compared with A_raw and by 49.6 percentage points compared with B_hardened.

These results are from the original experiment and should not be merged with later runs using different test sizes and thresholds.

### 5.2 Later risk-gate experiment

A later experiment used 70 test cases, 30 calibration cases, seed 7, and a selected threshold of 0.75.

| Configuration | Unsafe rate on attacked cases | Ideal outcome rate | Clean-case burden |
|---|---:|---:|---:|
| A_raw | 78.0% | 22.0% | 18.2% |
| B_hardened | 50.8% | 47.5% | 18.2% |
| C_graph_binary | 45.8% | 52.5% | 18.2% |
| E_abstain_only | 27.1% | 66.1% | 18.2% |
| D_full | 8.5% | 74.6% | 45.5% |

The full system achieved a lower unsafe-outcome rate than the baseline configurations. However, its clean-case burden was 45.5%, indicating a substantial trade-off between safety and unnecessary escalation.

The results therefore support evaluating the system using both unsafe outcomes and operational burden, rather than optimizing a single metric.

### 5.3 Provenance ablation

In the saved provenance experiment, the attacked-case comparison contained 59 cases per configuration.

| Configuration | Unsafe cases | Unsafe rate |
|---|---:|---:|
| D_full | 5/59 | 8.5% |
| F_provenance | 1/59 | 1.7% |

The observed absolute reduction was approximately 6.8 percentage points. The observed relative reduction was 80%, calculated from the reduction from five unsafe cases to one.

The measured clean-case burden was 5/11 (45.5%) for both configurations, and the reported number of missed incidents among clean cases was zero.

These are descriptive results from a small synthetic test set. They do not establish statistical significance or prove that provenance verification will provide the same improvement in other environments.

### 5.4 Failure analysis

The remaining unsafe case for F_provenance was `inject_conceal_stitched-000`. Its preferred outcome was PROPOSE, but the system returned CLOSE with the reason `llm_closed`.

This case represents a missed incident rather than an unsafe containment action. It illustrates that evidence-integrity controls cannot guarantee that the analyst model will make the correct final decision.

Two inspected `forgery_strong` cases were unsafe under D_full but were escalated under F_provenance because their claims became Unknown and the proposed actions were not justified by verified claims.

The benchmark also identifies strong forgery as a limitation: fabricated evidence that is indistinguishable from genuine evidence to the verifier cannot necessarily be detected using temporal consistency and graph structure alone. Cross-checking against an independently protected raw-log archive is a potential future safeguard.

## 6. Discussion

The experiments indicate that combining structured evidence verification, explicit uncertainty, and risk-aware routing can reduce unsafe decisions within the synthetic benchmark.

The ablation results in the saved summary show a particularly large increase in unsafe outcomes when three-state verification is removed. This supports the importance of representing uncertainty explicitly rather than forcing unsupported claims into a binary decision.

The provenance comparison is encouraging because the observed unsafe rate decreased from 8.5% to 1.7%. However, the small sample, synthetic scenarios, and simulated model mean that this finding should be treated as preliminary.

The high clean-case burden in the later D_full experiment is a practical concern. Excessive escalation can overwhelm analysts and reduce the operational usefulness of a security agent. Future evaluation should therefore examine the trade-off between unsafe actions, missed incidents, and analyst workload.

## 7. Limitations

1. **Simulated language model:** The main results use a seeded stand-in whose error rates are assumed. They do not demonstrate performance with Llama 3.1 8B.
2. **Synthetic benchmark:** The attack scenarios and ground truth were developed within the same project as the defense.
3. **Limited sample size:** The later experiments contain 70 test cases, with 59 attacked and 11 clean cases in the reported comparison.
4. **Strong forgery:** Valid-looking fabricated evidence may evade checks that rely on graph structure and event consistency.
5. **Provenance trust assumptions:** HMAC signatures do not guarantee the truthfulness of events signed by a compromised or untrusted ingestion system.
6. **Clean-case burden:** The later D_full experiment reports a 45.5% clean-case burden.
7. **External validity:** Real SOC logs, real alert distributions, production key management, and human analyst workflows have not been validated by these experiments.
8. **Prior-art review:** The work should not be described as the first or definitively novel method without a structured review of related research.

## 8. Future Work

- Run the experiment using the actual local model through Ollama and report its results separately.
- Add an independently protected raw-log archive for cross-checking suspicious graph events.
- Evaluate provenance verification under ingestion compromise and key-management failures.
- Test on attack chains derived from public security datasets.
- Expand the number and diversity of test cases.
- Evaluate the clean-case escalation burden and tune the threshold using calibration data only.
- Compare performance across multiple seeds and report uncertainty intervals for the provenance ablation.
- Integrate the project's graph and ingestion components through the documented JSONL interface.
- Conduct a structured literature review before making novelty claims.

## 9. Conclusion

This project implements a local SOC-agent architecture that separates model-generated incident recommendations from deterministic evidence verification and risk-aware decision routing.

The original synthetic experiment reported a reduction in unsafe outcomes from 81.0% for a raw model to 7.4% for the full system. A later experiment reported 8.5% unsafe outcomes for D_full, while the saved provenance comparison reported 1.7% for F_provenance. These results are encouraging within the benchmark, but the substantial clean-case burden, remaining missed incident, simulated model, and synthetic evaluation design limit the conclusions that can be drawn.

The next major validation step is to evaluate the system using a real local model and more independent security scenarios.

## Reproducibility Notes

- Preserve the original `results/` directory.
- Keep experiment outputs in separate folders.
- Record seed, number of scenarios per family, calibration size, test size, and threshold for every run.
- Retain `cases.csv`, `summary.md`, and `meta.json` for each experiment.
- Ensure the report distinguishes the original 563-test-case experiment from the later 70-test-case experiment.
- Do not describe simulated-model results as real Llama evaluation.
