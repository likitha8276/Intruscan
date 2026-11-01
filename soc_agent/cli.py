"""Command line: triage an alert against a JSONL event file with the chosen configuration.

    python -m soc_agent.cli triage --events events.jsonl --entity host-a --llm ollama --model llama3.1:8b
"""
from __future__ import annotations

import argparse
import json

from .agent import SOCAgent
from .config import VerifierConfig
from .evaluate import make_configs
from .io import load_events_jsonl, scenario_from_store
from .llm import OllamaClient, SimulatedLLM


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="soc_agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage")
    t.add_argument("--events", required=True)
    t.add_argument("--entity", action="append", required=True, help="alert entity (repeatable)")
    t.add_argument("--config", default="D_full",
                   choices=["A_raw", "B_hardened", "C_graph_binary", "E_abstain_only", "D_full"])
    t.add_argument("--llm", choices=["sim", "ollama"], default="ollama")
    t.add_argument("--model", default="llama3.1:8b")
    t.add_argument("--host", default="http://localhost:11434")
    t.add_argument("--tau", type=float, default=0.7)
    args = ap.parse_args(argv)

    store = load_events_jsonl(args.events)
    scn = scenario_from_store(store, tuple(args.entity))
    llm = OllamaClient(args.model, args.host) if args.llm == "ollama" else SimulatedLLM()
    agent = SOCAgent(llm, make_configs(VerifierConfig(tau=args.tau))[args.config])
    res = agent.run(scn)
    d = res.decision
    print(json.dumps({
        "outcome": d.outcome.value,
        "action": None if d.action is None else {"type": d.action.type, "target": d.action.target},
        "reasons": d.reasons, "verdicts": res.verdicts, "gate_flags": res.gate_flags,
        "llm_ms": round(res.llm_ms, 1), "verify_ms": round(res.verify_ms, 2),
    }, indent=2))


if __name__ == "__main__":
    main()
