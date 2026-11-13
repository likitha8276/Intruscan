"""Command line: triage an alert against a JSONL event file.

Example:
    python -m soc_agent.cli triage --events events.jsonl --entity host-a --llm auto
"""
from __future__ import annotations

import argparse
import json
import os

from dotenv import load_dotenv

from .agent import SOCAgent
from .config import VerifierConfig
from .evaluate import make_configs
from .io import load_events_jsonl, scenario_from_store
from .llm import FallbackLLM, GeminiClient, GroqClient, SimulatedLLM


def load_logs_json(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in data.items()
    ):
        raise ValueError("logs JSON must map event IDs to string excerpts")
    return data


def build_llm(mode: str, model: str):
    """Build the requested provider configuration."""
    if mode == "sim":
        return SimulatedLLM()
    if mode == "groq":
        return GroqClient(model=model)
    if mode == "gemini":
        return GeminiClient()
    if mode == "auto":
        if not os.environ.get("GROQ_API_KEY"):
            raise ValueError(
                "GROQ_API_KEY is missing. Add it to .env or choose --llm gemini/sim."
            )
        if not os.environ.get("GEMINI_API_KEY"):
            raise ValueError(
                "GEMINI_API_KEY is missing. Add it to .env or choose --llm groq/sim."
            )
        return FallbackLLM(
            primary=GroqClient(model=model),
            fallback=GeminiClient(),
        )
    raise ValueError(f"Unsupported LLM mode: {mode}")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--input", "--events", dest="events", help="event JSONL file")
    common.add_argument("--logs", help="JSON object mapping event IDs to log excerpts")
    common.add_argument(
        "--entity", action="append", help="alert entity (repeatable; inferred if omitted)"
    )
    common.add_argument(
        "--config",
        default="D_full",
        choices=["A_raw", "B_hardened", "C_graph_binary", "E_abstain_only", "D_full"],
    )
    common.add_argument(
        "--llm",
        choices=["auto", "groq", "gemini", "sim"],
        default="auto",
        help="LLM provider: auto (Groq then Gemini), groq, gemini, or sim",
    )
    common.add_argument("--model", default="openai/gpt-oss-20b", help="Groq model name")
    common.add_argument("--tau", type=float, default=0.7)

    parser = argparse.ArgumentParser(prog="soc_agent", parents=[common])
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("triage", parents=[common])
    return parser


def main(argv=None) -> None:
    load_dotenv()

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
    try:
        llm = build_llm(args.llm, args.model)
    except ValueError as exc:
        ap.error(str(exc))

    agent = SOCAgent(
        llm,
        make_configs(VerifierConfig(tau=args.tau))[args.config],
    )
    res = agent.run(scn)
    decision = res.decision
    print(
        json.dumps(
            {
                "outcome": decision.outcome.value,
                "action": None
                if decision.action is None
                else {"type": decision.action.type, "target": decision.action.target},
                "reasons": decision.reasons,
                "verdicts": res.verdicts,
                "gate_flags": res.gate_flags,
                "llm_ms": round(res.llm_ms, 1),
                "verify_ms": round(res.verify_ms, 2),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
