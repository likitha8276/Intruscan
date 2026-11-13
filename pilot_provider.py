"""Small real-provider integration pilot for the current SOC agent.

Example:
    python pilot_provider.py --llm auto --model openai/gpt-oss-20b
    python pilot_provider.py --llm groq --model openai/gpt-oss-20b
    python pilot_provider.py --llm gemini

This is an integration smoke test, not a benchmark. Its output directory is
separate from the historical results_llama_pilot_v1 artifacts.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from dataclasses import asdict

from dotenv import load_dotenv

from soc_agent.attacks import build_dataset
from soc_agent.agent import SOCAgent
from soc_agent.config import VerifierConfig
from soc_agent.evaluate import make_configs, score
from soc_agent.llm import CachedLLM, FallbackLLM, GeminiClient, GroqClient


FAMILIES = ["inject_conceal_atomic", "forgery_strong"]
CONFIG_NAMES = ["A_raw", "D_full"]


def build_llm(mode: str, model: str):
    if mode == "groq":
        client = GroqClient(model=model)
    elif mode == "gemini":
        client = GeminiClient()
    else:
        if not os.getenv("GROQ_API_KEY") or not os.getenv("GEMINI_API_KEY"):
            raise RuntimeError(
                "--llm auto requires both GROQ_API_KEY and GEMINI_API_KEY in the environment"
            )
        client = FallbackLLM(GroqClient(model=model), GeminiClient())
    return CachedLLM(client)


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run a small SOC real-provider integration pilot.")
    parser.add_argument("--llm", choices=["auto", "groq", "gemini"], default="auto")
    parser.add_argument("--model", default="openai/gpt-oss-20b")
    parser.add_argument("--out", default="results_provider_pilot_v1")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--n-per-family", type=int, default=1)
    parser.add_argument("--tau", type=float, default=0.70)
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=False)

    dataset = build_dataset(args.n_per_family, seed=args.seed, families=FAMILIES)
    llm = build_llm(args.llm, args.model)
    configs_all = make_configs(VerifierConfig(tau=args.tau))
    configs = {name: configs_all[name] for name in CONFIG_NAMES}

    rows = []
    details = []

    for scenario in dataset:
        for name, config in configs.items():
            print(f"Running {scenario.case_id} with {name}...", flush=True)
            result = SOCAgent(llm, config).run(scenario)
            row = score(scenario, result)
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

    with open(os.path.join(args.out, "cases.csv"), "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    with open(os.path.join(args.out, "details.json"), "w", encoding="utf-8") as file:
        json.dump(details, file, indent=2)

    if args.llm == "auto":
        model_label = (
            f"Groq ({args.model}) -> Gemini "
            f"({os.getenv('GEMINI_MODEL', 'gemini-3.8-flash')})"
        )
    elif args.llm == "gemini":
        model_label = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    else:
        model_label = args.model

    with open(os.path.join(args.out, "meta.json"), "w", encoding="utf-8") as file:
        json.dump({
            "llm": args.llm,
            "model": model_label,
            "seed": args.seed,
            "families": FAMILIES,
            "n_per_family": args.n_per_family,
            "tau": args.tau,
            "configs": list(configs),
            "purpose": "small real-provider integration pilot; not a benchmark",
        }, file, indent=2)

    print(f"\nPilot finished. Results saved in {args.out}", flush=True)


if __name__ == "__main__":
    main()