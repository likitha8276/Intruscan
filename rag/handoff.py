"""RAG-enriched handoff: group SLOW_BRAIN flows into per-source incidents and call the
Layer 4 SOC CLI once per incident (same CLI flags as tools/slow_brain_handoff.py).

python -m rag.handoff --scored scored_flows.jsonl --output rag_soc_alerts.jsonl --llm auto --model openai/gpt-oss-20b
"""
import argparse, json, logging, subprocess, sys, tempfile
from collections import defaultdict
from pathlib import Path
from .bridge import build, BASE_PREFIX

LOG = logging.getLogger("rag.handoff")
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _err(status, reason, stdout="", stderr=""):
    return {"status": status, "outcome": status, "verdicts": [], "gate_flags": [],
            "reasons": [reason], "stdout": stdout, "stderr": stderr}


def run_incident(src, events, logs, python, model, config, timeout, root, max_entities=5, llm="auto"):
    with tempfile.TemporaryDirectory(prefix="rag-incident-") as d:
        ev, lg = Path(d) / "events.jsonl", Path(d) / "logs.json"
        ev.write_text("".join(json.dumps(e) + "\\n" for e in events), encoding="utf-8")
        lg.write_text(json.dumps({e["event_id"]: logs[e["event_id"]] for e in events}), encoding="utf-8")
        entities = [src] + sorted({e["dst"] for e in events})[: max_entities - 1]
        cmd = [python, "-m", "soc_agent.cli", "--input", str(ev), "--logs", str(lg)]
        for x in entities:
            cmd += ["--entity", x]
        cmd += ["--config", config, "--llm", llm, "--model", model]
        try:
            r = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                               timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return _err("TIMEOUT", f"Slow Brain timed out after {timeout:g} seconds")
        except OSError as exc:
            return _err("CLI_ERROR", f"could not start SOC CLI: {exc}")
    if r.returncode != 0:
        return _err("CLI_ERROR", f"SOC CLI exited with status {r.returncode}",
                    r.stdout.strip(), r.stderr.strip())
    try:
        out = json.loads(r.stdout.strip())
        if not isinstance(out, dict):
            raise ValueError("SOC CLI output must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        return _err("CLI_OUTPUT_ERROR", str(exc), r.stdout.strip(), r.stderr.strip())
    out["status"] = "OK"
    return out


def run(scored, output, index, python=sys.executable, model="openai/gpt-oss-20b",
        config="D_full", timeout=300.0,
        max_events=12, root=PROJECT_ROOT, baseline_path=None, baseline_label=None, llm="auto"):
    events, logs, skipped = build(scored, index, baseline_path=baseline_path, baseline_label=baseline_label)
    groups = defaultdict(list)
    for e in events:
        groups[e["src"]].append(e)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "a", encoding="utf-8") as dest:
        for src, evs in groups.items():
            base = [e for e in evs if e["event_id"].startswith(BASE_PREFIX)][:5]
            inc = [e for e in evs if not e["event_id"].startswith(BASE_PREFIX)]
            # the agent shows at most 16 log lines (soc_agent max_log_lines); baseline events always
            # ride along, and a scanner can own thousands of flows, so the incident part is capped
            sent = base + inc[:max_events]
            result = run_incident(src, sent, logs, python, model, config, timeout, root, llm=llm)
            dest.write(json.dumps({"src": src, "event_ids": [e["event_id"] for e in sent],
                                   "events_total": len(inc), "events_sent": len(sent),
                                   "soc_result": result}, ensure_ascii=False) + "\\n")
            dest.flush()
            LOG.info("incident src=%s events=%d/%d status=%s", src, len(sent), len(inc), result["status"])
    return len(groups), len(events), skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scored", type=Path, default=Path("scored_flows.jsonl"))
    ap.add_argument("--output", type=Path, default=Path("rag_soc_alerts.jsonl"))
    ap.add_argument("--chroma-path", default="chroma_db")
    ap.add_argument("--baseline-file", default=None, help="normal flows the fast brain was trained on")
    ap.add_argument("--baseline-label", default=None, help="label that marks normal flows in that file")
    ap.add_argument("--min-conf", type=float, default=0.30)
    ap.add_argument("--gap", type=float, default=0.10)
    ap.add_argument("--max-hits", type=int, default=2)
    ap.add_argument("--mitre", choices=["seed", "full"], default="full")
    ap.add_argument("--mitre-scope", choices=["network", "flow", "all"], default="network")
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--llm", choices=["auto", "groq", "gemini", "sim"], default="auto")
    ap.add_argument("--model", default="openai/gpt-oss-20b")
    ap.add_argument("--config", default="D_full")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--max-events", type=int, default=12)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from . import bridge as _bridge
    _bridge.MIN_CONF, _bridge.GAP, _bridge.MAX_HITS = a.min_conf, a.gap, a.max_hits
    from .mitre_store import make_index
    n_inc, n_ev, skipped = run(a.scored, a.output, make_index(a.mitre, a.chroma_path, a.mitre_scope), a.python,
                               a.model, a.config, a.timeout, a.max_events,
                               baseline_path=a.baseline_file, baseline_label=a.baseline_label, llm=a.llm)
    LOG.info("done incidents=%d events=%d skipped=%d", n_inc, n_ev, skipped)


if __name__ == "__main__":
    main()