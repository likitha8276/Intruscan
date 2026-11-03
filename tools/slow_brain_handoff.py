#!/usr/bin/env python3
"""Route SLOW_BRAIN flows through the existing Layer 4 SOC CLI."""

from __future__ import annotations

import argparse
import json
import logging
import math
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger("intruscan.slow_brain_handoff")
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def first_value(flow: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in flow and flow[name] is not None:
            return flow[name]
    return None


def map_flow_to_event(flow: dict[str, Any]) -> dict[str, Any]:
    flow_id = flow.get("flow_id")
    timestamp = first_value(flow, "timestamp", "ts")
    source_ip = first_value(flow, "source_ip", "src_ip")
    dest_ip = first_value(flow, "dest_ip", "dst_ip")
    protocol = flow.get("protocol")
    if not isinstance(flow_id, str) or not flow_id.strip():
        raise ValueError("flow_id must be a non-empty string")
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError("timestamp or ts is required by the SOC event schema")
    if not isinstance(source_ip, str) or not source_ip.strip():
        raise ValueError("source_ip or src_ip is required")
    if not isinstance(dest_ip, str) or not dest_ip.strip():
        raise ValueError("dest_ip or dst_ip is required")
    if not isinstance(protocol, (str, int)) or not str(protocol).strip():
        raise ValueError("protocol is required")

    protocol_text = str(protocol).strip()
    event = dict(flow)
    event.update(
        {
            "event_id": flow_id,
            "ts": timestamp,
            "rel": f"network_flow_{protocol_text.lower()}",
            "src": source_ip,
            "dst": dest_ip,
            "source_system": "netflow",
            "parse_conf": 1.0,
            "match_conf": 1.0,
        }
    )
    return event


def run_slow_brain(
    flow: dict[str, Any],
    python_executable: str,
    model: str,
    host: str,
    config: str,
    timeout: float,
) -> dict[str, Any]:
    event = map_flow_to_event(flow)
    flow_id = str(event["event_id"])
    with tempfile.TemporaryDirectory(prefix="intruscan-slow-brain-") as directory:
        temp_dir = Path(directory)
        event_path = temp_dir / "event.jsonl"
        logs_path = temp_dir / "flow_context.json"
        event_path.write_text(
            json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        logs_path.write_text(
            json.dumps({flow_id: json.dumps(flow, ensure_ascii=False, allow_nan=False)}),
            encoding="utf-8",
        )
        command = [
            python_executable,
            "-m",
            "soc_agent.cli",
            "--input",
            str(event_path),
            "--logs",
            str(logs_path),
            "--entity",
            str(event["src"]),
            "--entity",
            str(event["dst"]),
            "--config",
            config,
            "--llm",
            "ollama",
            "--model",
            model,
            "--host",
            host,
        ]
        LOGGER.info("invoking Slow Brain flow_id=%s", flow_id)
        try:
            result = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            LOGGER.error("Slow Brain timed out flow_id=%s timeout=%.1fs", flow_id, timeout)
            return {
                "status": "TIMEOUT",
                "outcome": "TIMEOUT",
                "verdicts": ["TIMEOUT"],
                "gate_flags": [],
                "reasons": [f"Slow Brain timed out after {timeout:g} seconds"],
                "stdout": decode_output(exc.stdout),
                "stderr": decode_output(exc.stderr),
            }
        except OSError as exc:
            LOGGER.exception("failed to invoke SOC CLI flow_id=%s", flow_id)
            return {
                "status": "CLI_ERROR",
                "outcome": "CLI_ERROR",
                "verdicts": [],
                "gate_flags": [],
                "reasons": [f"could not start SOC CLI: {exc}"],
                "stdout": "",
                "stderr": str(exc),
            }

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    if result.returncode != 0:
        LOGGER.error(
            "SOC CLI failed flow_id=%s exit_code=%d stderr=%s",
            flow_id,
            result.returncode,
            stderr,
        )
        return {
            "status": "CLI_ERROR",
            "outcome": "CLI_ERROR",
            "verdicts": [],
            "gate_flags": [],
            "reasons": [f"SOC CLI exited with status {result.returncode}"],
            "stdout": stdout,
            "stderr": stderr,
        }
    try:
        agent_result = json.loads(stdout)
        if not isinstance(agent_result, dict):
            raise ValueError("SOC CLI output must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        LOGGER.error("SOC CLI returned invalid JSON flow_id=%s: %s", flow_id, exc)
        return {
            "status": "CLI_OUTPUT_ERROR",
            "outcome": "CLI_OUTPUT_ERROR",
            "verdicts": [],
            "gate_flags": [],
            "reasons": [str(exc)],
            "stdout": stdout,
            "stderr": stderr,
        }

    agent_result["status"] = "OK"
    if stderr:
        agent_result["stderr"] = stderr
    return agent_result


def decode_output(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def process_file(
    input_path: Path,
    output_path: Path,
    python_executable: str,
    model: str,
    host: str,
    config: str,
    timeout: float,
) -> tuple[int, int, int]:
    if input_path.resolve() == output_path.resolve():
        raise ValueError("input and output paths must be different")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    processed = ignored = invalid = 0

    with input_path.open("r", encoding="utf-8") as source, output_path.open(
        "a", encoding="utf-8"
    ) as destination:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                flow = json.loads(line)
                if not isinstance(flow, dict):
                    raise ValueError("JSONL row must be an object")
            except (json.JSONDecodeError, ValueError) as exc:
                LOGGER.error("invalid input line=%d: %s", line_number, exc)
                invalid += 1
                continue

            if flow.get("route") != "SLOW_BRAIN":
                ignored += 1
                LOGGER.debug(
                    "ignored flow_id=%s route=%s",
                    flow.get("flow_id", "unknown"),
                    flow.get("route"),
                )
                continue

            try:
                result = run_slow_brain(
                    flow, python_executable, model, host, config, timeout
                )
            except (TypeError, ValueError, OSError) as exc:
                LOGGER.exception(
                    "invalid flow line=%d flow_id=%s",
                    line_number,
                    flow.get("flow_id", "unknown"),
                )
                invalid += 1
                result = {
                    "status": "INVALID_FLOW",
                    "outcome": "INVALID_FLOW",
                    "verdicts": [],
                    "gate_flags": [],
                    "reasons": [str(exc)],
                }

            enriched = dict(flow)
            enriched["soc_result"] = result
            destination.write(
                json.dumps(enriched, ensure_ascii=False, allow_nan=False) + "\n"
            )
            destination.flush()
            processed += 1
            LOGGER.info(
                "saved result flow_id=%s status=%s",
                flow.get("flow_id", "unknown"),
                result.get("status", "UNKNOWN"),
            )
    return processed, ignored, invalid


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Hand SLOW_BRAIN flows to the Layer 4 SOC CLI."
    )
    parser.add_argument("--input", type=Path, default=Path("scored_flows.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("final_soc_alerts.jsonl"))
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--config", default="D_full")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite positive number")

    try:
        processed, ignored, invalid = process_file(
            args.input,
            args.output,
            args.python,
            args.model,
            args.host,
            args.config,
            args.timeout,
        )
    except (OSError, ValueError) as exc:
        LOGGER.error("handoff failed: %s", exc)
        return 1
    LOGGER.info(
        "complete processed=%d ignored=%d invalid=%d output=%s",
        processed,
        ignored,
        invalid,
        args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
