import csv
import json
import os
import sys
from dataclasses import asdict

from soc_agent.attacks import build_dataset
from soc_agent.agent import SOCAgent
from soc_agent.config import VerifierConfig
from soc_agent.evaluate import make_configs, score
from soc_agent.llm import CachedLLM, OllamaClient

OUT = "results_llama_pilot_v1"
os.makedirs(OUT, exist_ok=False)

families = ["inject_conceal_atomic", "forgery_strong"]
dataset = build_dataset(1, seed=7, families=families)
llm = CachedLLM(OllamaClient(model="llama3.1:8b", num_ctx=8192))
configs_all = make_configs(VerifierConfig(tau=0.70))
configs = {name: configs_all[name] for name in ["A_raw", "D_full"]}

rows = []
details = []

for scn in dataset:
    for name, cfg in configs.items():
        print(f"Running {scn.case_id} with {name}...", flush=True)
        result = SOCAgent(llm, cfg).run(scn)
        row = score(scn, result)
        rows.append(asdict(row))
        details.append({
            "case_id": result.case_id,
            "config": result.config,
            "outcome": result.decision.outcome.value,
            "reasons": result.decision.reasons,
            "parsed_ok": result.parsed_ok,
            "llm_ms": result.llm_ms,
            "verify_ms": result.verify_ms,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "verdicts": result.verdicts,
            "gate_flags": result.gate_flags,
        })

with open(os.path.join(OUT, "cases.csv"), "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

with open(os.path.join(OUT, "details.json"), "w", encoding="utf-8") as f:
    json.dump(details, f, indent=2)

with open(os.path.join(OUT, "meta.json"), "w", encoding="utf-8") as f:
    json.dump({
        "llm": "ollama",
        "model": "llama3.1:8b",
        "seed": 7,
        "families": families,
        "n_per_family": 1,
        "tau": 0.70,
        "configs": list(configs),
        "purpose": "small real-model integration pilot; not a benchmark",
    }, f, indent=2)

print(f"\nPilot finished. Results saved in {OUT}", flush=True)
