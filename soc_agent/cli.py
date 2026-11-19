"""Command line: triage an alert against a JSONL event file.

Example:
    python -m soc_agent.cli triage --events events.jsonl --entity host-a --llm auto
"""
from __future__ import annotations

import argparse
import json
import os
import warnings

from dotenv import load_dotenv

from .agent import SOCAgent
from .config import VerifierConfig
from .evaluate import make_configs
from .io import load_events_jsonl, scenario_from_store
from .llm import FallbackLLM, GeminiClient, GroqClient, ProviderChain,SimulatedLLM


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
        providers = []
        if os.environ.get("GROQ_API_KEY"):
            providers.append(("groq", GroqClient(model=model)))
            backup = os.environ.get("GROQ_BACKUP_MODEL", "openai/gpt-oss-120b")
            if backup != model:
                providers.append(("groq_backup", GroqClient(model=backup)))
        if os.environ.get("GEMINI_API_KEY"):
            providers.append(("gemini", GeminiClient()))
        if not providers:
            raise ValueError(
                "No LLM keys found. Set GROQ_API_KEY and/or GEMINI_API_KEY, "
                "or choose --llm sim."
            )
        return ProviderChain(providers)


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
        choices=["A_raw", "B_hardened", "C_graph_binary", "E_abstain_only", "D_full", "D_full_rel"],
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

    provenance_secret = os.environ.get("SOC_PROVENANCE_KEY")
    provenance_key = provenance_secret.encode("utf-8") if provenance_secret else None
    if provenance_key is None:
        warnings.warn(
            "SOC_PROVENANCE_KEY is not configured; provenance verification is disabled.",
            RuntimeWarning,
            stacklevel=2,
        )

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

    verifier_config = VerifierConfig(
        tau=args.tau,
        require_provenance=provenance_key is not None,
        provenance_key=provenance_key,
    )
    agent = SOCAgent(
        llm,
        make_configs(verifier_config)[args.config],
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
                "llm_ms": round(res.llm_ms, 1),
                "verify_ms": round(res.verify_ms, 2),
                "tool_steps": res.tool_steps,
                "revised": res.revised,
                "llm_error": res.llm_error,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
