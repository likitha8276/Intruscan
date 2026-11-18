"""RAG-enriched handoff: group SLOW_BRAIN flows into per-source incidents and call the
Layer 4 SOC CLI once per incident (same CLI flags as tools/slow_brain_handoff.py).

python -m rag.handoff --scored scored_flows.jsonl --output rag_soc_alerts.jsonl --llm auto --model openai/gpt-oss-20b
"""
import argparse, json, logging, subprocess, sys, tempfile
from collections import defaultdict
from pathlib import Path
from .bridge import build, BASE_PREFIX
from soc_agent import incidents as inc_mod

LOG = logging.getLogger("rag.handoff")
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _err(status, reason, stdout="", stderr=""):
    return {"status": status, "outcome": status, "verdicts": [], "gate_flags": [],
            "reasons": [reason], "stdout": stdout, "stderr": stderr}


def run_incident(src, events, logs, python, model, config, timeout, root, max_entities=5, llm="auto"):
    with tempfile.TemporaryDirectory(prefix="rag-incident-") as d:
        ev, lg = Path(d) / "events.jsonl", Path(d) / "logs.json"
        ev.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
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
        max_events=12, root=PROJECT_ROOT, baseline_path=None, baseline_label=None, llm="auto",
        incident_store=None, run_context=None):
    """Group SLOW_BRAIN flows per source and call the SOC CLI once per source.

    With `incident_store` (a soc_agent.incidents.IncidentStore) every analysed source, every
    untimed flow (missing/surrogate timestamp, never sent to the LLM) and the result metadata is
    also recorded as an incident. `run_context` may carry model_sha256 / feature_set / thresholds.
    """
    untimed, meta = [], {}
    events, logs, skipped = build(scored, index, baseline_path=baseline_path, baseline_label=baseline_label,
                                  untimed_out=untimed, meta_out=meta)
    ctx = run_context or {}
    if incident_store is not None:
        for raw in untimed:
            try:
                incident_store.save(inc_mod.untimed_incident(raw, **ctx))
            except ValueError as exc:
                LOG.error("cannot record untimed flow: %s", exc)
    if untimed:
        LOG.warning("%d SLOW_BRAIN flows have missing/surrogate timestamps; not sent to the LLM", len(untimed))
    groups = defaultdict(list)
    for e in events:
        groups[e["src"]].append(e)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as dest:
        for src, evs in groups.items():
            base = [e for e in evs if e["event_id"].startswith(BASE_PREFIX)][:5]
            inc = [e for e in evs if not e["event_id"].startswith(BASE_PREFIX)]
            # the agent shows at most 16 log lines (soc_agent max_log_lines); baseline events always
            # ride along, and a scanner can own thousands of flows, so the incident part is capped
            sent = base + inc[:max_events]
            result = run_incident(src, sent, logs, python, model, config, timeout, root, llm=llm)
            dest.write(json.dumps({"src": src, "event_ids": [e["event_id"] for e in sent],
                                   "events_total": len(inc), "events_sent": len(sent),
                                   "soc_result": result}, ensure_ascii=False) + "\n")
            dest.flush()
            if incident_store is not None:
                mitre = [dict(h, event_id=e["event_id"]) for e in sent for h in meta.get(e["event_id"], {}).get("mitre", [])]
                incident_store.save(inc_mod.slow_brain_incident(
                    src=src, events=sent, logs=logs, soc_result=result, mitre=mitre,
                    flows=[{"s_score": meta.get(e["event_id"], {}).get("s_score")} for e in sent], **ctx), replace=True)
            LOG.info("incident src=%s events=%d/%d status=%s", src, len(sent), len(inc), result["status"])
    return len(groups), len(events), skipped


def run_fast_track(scored, output, index, python, model, config, timeout, max_events, root, llm,
                   incident_store, run_context, baseline_path=None, baseline_label=None):
    """Agent -> verifier -> risk gate for FAST_TRACK flows. No RAG. Results go into the existing FT incidents."""
    meta = {}
    events, logs, skipped = build(scored, index, baseline_path=baseline_path, baseline_label=baseline_label,
                                  meta_out=meta, routes=("FAST_TRACK",), skip_rag=True)
    groups = defaultdict(list)
    for e in events:
        groups[e["src"]].append(e)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as dest:
        for src, evs in groups.items():
            base = [e for e in evs if e["event_id"].startswith(BASE_PREFIX)][:5]
            inc = [e for e in evs if not e["event_id"].startswith(BASE_PREFIX)]
            sent = base + inc[:max_events]
            result = inc_mod.apply_fast_track_floor(
                run_incident(src, sent, logs, python, model, config, timeout, root, llm=llm))
            flow_ids = sorted({meta[e["event_id"]]["flow_id"] for e in inc if meta.get(e["event_id"], {}).get("flow_id")})
            coverage = {"events_sent": min(len(inc), max_events), "events_total": len(inc)}
            n = inc_mod.attach_agent_result(incident_store, flow_ids, result, coverage) if incident_store else 0
            dest.write(json.dumps({"src": src, "route": "FAST_TRACK", "soc_result": result,
                                   "coverage": coverage}, ensure_ascii=False) + "\n")
            dest.flush()
            LOG.info("fast-track src=%s flows=%d attached=%d status=%s", src, len(inc), n, result["status"])
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
    ap.add_argument("--incident-db", type=Path, default=None,
                    help="also record incidents (Slow Brain, FAST_TRACK, untimed) in this SQLite store")
    ap.add_argument("--fast-brain-model", default=None,
                    help="trusted model .joblib; its fingerprint and feature set are stored with incidents")
    ap.add_argument("--thresholds", default=None, help="approved thresholds file (with --fast-brain-model)")
    ap.add_argument("--fast-track-agent", action="store_true",
                    help="also run FAST_TRACK flows through the agent, verifier and risk gate (no RAG)")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from . import bridge as _bridge
    _bridge.MIN_CONF, _bridge.GAP, _bridge.MAX_HITS = a.min_conf, a.gap, a.max_hits
    from .mitre_store import make_index
    store, ctx = None, None
    if a.incident_db:
        store = inc_mod.IncidentStore(a.incident_db)
        ctx = (inc_mod.run_context_from_model(a.fast_brain_model, a.thresholds) if a.fast_brain_model else {})
        counts = inc_mod.record_scored_file(a.scored, store, ctx, include_untimed=False)
        LOG.info("FAST_TRACK incidents recorded (no LLM): %s", counts)
    n_inc, n_ev, skipped = run(a.scored, a.output, make_index(a.mitre, a.chroma_path, a.mitre_scope), a.python,
                               a.model, a.config, a.timeout, a.max_events,
                               baseline_path=a.baseline_file, baseline_label=a.baseline_label, llm=a.llm,
                               incident_store=store, run_context=ctx)
    LOG.info("done incidents=%d events=%d skipped=%d", n_inc, n_ev, skipped)
    if a.fast_track_agent:
        ft = run_fast_track(a.scored, a.output.with_name(a.output.stem + "_fast_track.jsonl"), None, a.python,
                            a.model, a.config, a.timeout, a.max_events, PROJECT_ROOT, a.llm, store, ctx,
                            baseline_path=a.baseline_file, baseline_label=a.baseline_label)
        LOG.info("fast-track agent done sources=%d events=%d skipped=%d", *ft)


if __name__ == "__main__":
    main()