"""Run the full experiment: calibrate on the calibration split, evaluate on the test split.

    python -m soc_agent.run_experiments --n 40 --seed 7 --llm sim --out results
    python -m soc_agent.run_experiments --n 10 --llm ollama --model llama3.1:8b --out results_ollama
"""
from __future__ import annotations

import argparse
import json
import os
import time

from .attacks import build_dataset
from .config import VerifierConfig
from .evaluate import (MAIN, calibrate_tau, headline, make_ablations, make_configs, md_families,
                       md_headline, md_paired, run_configs, split_dataset, write_csv)
from .llm import CachedLLM, OllamaClient, SimProfile, SimulatedLLM


def build_llm(args, scale: float = 1.0):
    if args.llm == "ollama":
        return CachedLLM(OllamaClient(model=args.model, host=args.host, num_ctx=args.num_ctx))
    return CachedLLM(SimulatedLLM(SimProfile().scaled(scale)))


def main(argv=None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40, help="cases per attack family")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--llm", choices=["sim", "ollama"], default="sim")
    ap.add_argument("--model", default="llama3.1:8b")
    ap.add_argument("--host", default="http://localhost:11434")
    ap.add_argument("--num-ctx", type=int, default=8192)
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
                                ("C_graph_binary", "D_full"), ("E_abstain_only", "D_full"),
                                ("D_full", "F_verifier_provenance"),
                                ("F_verifier_provenance", "G_full_provenance")])
    meta = {"llm": args.llm, "model": args.model if args.llm == "ollama" else "simulated-8b-standin",
            "seed": args.seed, "n_per_family": args.n, "calib_cases": len(calib), "test_cases": len(test),
            "tau_chosen": tau, "tau_grid_objective": {str(k): round(v_, 4) for k, v_ in grid.items()},
            "max_age_h": v.max_age.total_seconds() / 3600, "runtime_s": round(time.time() - t0, 1)}
    with open(os.path.join(args.out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    note = ("> **Simulated LLM.** These numbers come from a seeded stand-in for an 8B model whose fault "
            "rates are assumptions (see `SimProfile`). They validate the pipeline and harness, not Llama.\n\n"
            if args.llm == "sim" else "")
    with open(os.path.join(args.out, "summary.md"), "w") as f:
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
        with open(os.path.join(args.out, "sensitivity.md"), "w") as f:
            f.write("# Sensitivity of attacked-case unsafe rate to simulated LLM fault rates\n\n" + "\n".join(lines) + "\n")

    print(main_tbl)
    print(f"tau={tau}  test={len(test)}  calib={len(calib)}  -> {args.out}/")


if __name__ == "__main__":
    main()
