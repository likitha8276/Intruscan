"""Run the full experiment: calibrate on the calibration split, evaluate on the test split.

    python -m soc_agent.run_experiments --n 40 --seed 7 --llm sim --out results
    python -m soc_agent.run_experiments --n 10 --llm auto --model openai/gpt-oss-20b --out results_auto
"""
from __future__ import annotations

import argparse
import json
import os
import time

from dotenv import load_dotenv

from .attacks import build_dataset
from .config import VerifierConfig
from .evaluate import (MAIN, calibrate_tau, headline, make_ablations, make_configs, md_families,
                       md_headline, md_paired, run_configs, split_dataset, write_csv)
from .llm import CachedLLM, FallbackLLM, GeminiClient, GroqClient, SimProfile, SimulatedLLM


def build_llm(args, scale: float = 1.0):
    """Build the selected LLM while retaining response caching for experiments."""
    if args.llm == "groq":
        client = GroqClient(model=args.model)
    elif args.llm == "gemini":
        client = GeminiClient()
    elif args.llm == "auto":
        if not os.getenv("GROQ_API_KEY") or not os.getenv("GEMINI_API_KEY"):
            raise RuntimeError(
                "--llm auto requires both GROQ_API_KEY and GEMINI_API_KEY to be set"
            )
        client = FallbackLLM(
            GroqClient(model=args.model),
            GeminiClient(),
        )
    else:
        return CachedLLM(SimulatedLLM(SimProfile().scaled(scale)))
    return CachedLLM(client)


def main(argv=None) -> None:
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40, help="cases per attack family")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--llm", choices=["sim", "groq", "gemini", "auto"], default="sim")
    ap.add_argument("--model", default="openai/gpt-oss-20b")
    ap.add_argument("--out", default="results")
    ap.add_argument("--sensitivity", action="store_true", help="repeat with scaled simulated fault rates")
    ap.add_argument("--no-plot", action="store_true")
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)

    t0 = time.time()
    ds = build_dataset(args.n, args.seed)
    calib, test = split_dataset(ds)
    llm = build_llm(args)

    tau, grid = calibrate_tau(calib, llm)
    v = VerifierConfig(tau=tau)
    configs = {**make_configs(v), **make_ablations(v)}
    rows = run_configs(configs, test, llm)
    write_csv(rows, os.path.join(args.out, "cases.csv"))

    abl = [c for c in configs if c.startswith("D-")]
    main_tbl = md_headline(rows, MAIN, ref="A_raw")
    abl_tbl = md_headline(rows, ["D_full"] + abl, ref="D_full")
    fam_tbl = md_families(rows, MAIN)
    pair_tbl = md_paired(rows, [("A_raw", "D_full"), ("B_hardened", "D_full"),
                                ("C_graph_binary", "D_full"), ("E_abstain_only", "D_full")])
    if args.llm == "sim":
        model_label = "simulated-8b-standin"
    elif args.llm == "groq":
        model_label = args.model
    elif args.llm == "gemini":
        model_label = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    else:
        model_label = f"Groq ({args.model}) -> Gemini ({os.getenv('GEMINI_MODEL', 'gemini-3.8-flash')})"
    meta = {"llm": args.llm, "model": model_label,
            "seed": args.seed, "n_per_family": args.n, "calib_cases": len(calib), "test_cases": len(test),
            "tau_chosen": tau, "tau_grid_objective": {str(k): round(v_, 4) for k, v_ in grid.items()},
            "max_age_h": v.max_age.total_seconds() / 3600, "runtime_s": round(time.time() - t0, 1)}
    with open(os.path.join(args.out, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    note = ("> **Simulated LLM.** These numbers come from a seeded stand-in for an 8B model whose fault "
            "rates are assumptions (see `SimProfile`). They validate the pipeline and harness, not a "
            "real deployed model.\n\n" if args.llm == "sim" else "")
    if args.llm == "auto":
        note += ("> **Provider fallback.** Groq is attempted first; Gemini is used only for transient "
                 "provider failures. Results may vary across provider/model versions.\n\n")
    with open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8") as f:
        f.write(f"# Results\n\n{note}Test cases: {len(test)} (calibration: {len(calib)}); "
                f"tau={tau} chosen on calibration only.\n\n## Main comparison\n\n{main_tbl}\n"
                f"## Per-family unsafe rate\n\n{fam_tbl}\n## Ablations (delta vs D_full)\n\n{abl_tbl}\n"
                f"## Paired tests on attacked cases\n\n{pair_tbl}\n")

    if not args.no_plot:
        try:
            from .report import plot_families
            plot_families(rows, os.path.join(args.out, "unsafe_by_family.png"))
        except Exception as e:  # plotting is optional
            print("plot skipped:", e)

    if args.sensitivity and args.llm == "sim":
        lines = ["| fault-rate scale | A_raw | B_hardened | C_graph_binary | E_abstain_only | D_full |",
                 "|---|---|---|---|---|---|"]
        for s in (0.5, 1.0, 1.5):
            r = run_configs({k: configs[k] for k in MAIN}, test, build_llm(args, s))
            lines.append(f"| {s}x | " + " | ".join(f"{100 * headline(r, c)['unsafe']:.1f}%" for c in MAIN) + " |")
        with open(os.path.join(args.out, "sensitivity.md"), "w", encoding="utf-8") as f:
            f.write("# Sensitivity of attacked-case unsafe rate to simulated LLM fault rates\n\n" + "\n".join(lines) + "\n")

    print(main_tbl)
    print(f"tau={tau}  test={len(test)}  calib={len(calib)}  -> {args.out}/")


if __name__ == "__main__":
    main()