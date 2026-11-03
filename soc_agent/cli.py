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


def load_logs_json(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in data.items()
    ):
        raise ValueError("logs JSON must map event IDs to string excerpts")
    return data


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--input", "--events", dest="events", help="event JSONL file")
    common.add_argument("--logs", help="JSON object mapping event IDs to log excerpts")
    common.add_argument(
        "--entity", action="append", help="alert entity (repeatable; inferred if omitted)"
    )
    common.add_argument(
        "--config", default="D_full",
        choices=["A_raw", "B_hardened", "C_graph_binary", "E_abstain_only", "D_full"],
    )
    common.add_argument("--llm", choices=["sim", "ollama"], default="ollama")
    common.add_argument("--model", default="llama3.1:8b")
    common.add_argument("--host", default="http://localhost:11434")
    common.add_argument("--tau", type=float, default=0.7)

    parser = argparse.ArgumentParser(prog="soc_agent", parents=[common])
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("triage", parents=[common])
    return parser


def main(argv=None) -> None:
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.cmd not in (None, "triage"):
        ap.error("unsupported command")
    if not args.events:
        ap.error("provide --input/--events with an event JSONL file")

    store = load_events_jsonl(args.events)
    logs = load_logs_json(args.logs) if args.logs else None
    entities = args.entity
    if not entities:
        entities = sorted(str(entity) for entity in store.g.nodes)
    if not entities:
        ap.error("cannot infer alert entities from an empty event file; pass --entity")
    scn = scenario_from_store(store, tuple(entities), logs=logs)
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
