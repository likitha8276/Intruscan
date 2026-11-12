"""scored_flows.jsonl (Layer 2) -> events + logs for the Layer 4 SOC CLI.

Events: one rel="connect" event per SLOW_BRAIN flow, plus one "baseline_connect" summary event
per authorized host pair (>= min_support cleared flows before the incident), so the agent's
evidence graph can actually contain "this pair talks routinely". logs: {event_id: text}.
The ground truth `label` is never copied into events or logs.
"""
import argparse, json, sys
from datetime import timedelta
from .graph_store import FlowGraph, parse_ts
from .event_builder import normalize, SrcStats, infer_behavior, describe, behavior_stats, build_event

BASE_PREFIX = "BASE-"

# Retrieval filtering. Starting values from python -m rag.retrieval_check output, not calibrated constants.
# Cosine confidence does NOT separate right from wrong matches on the full ATT&CK matrix (a wrong match
# scored 0.55 while a right one scored 0.37), so the matches are shown as candidates, not verdicts.
MIN_CONF = 0.30        # hide matches below this cosine confidence
GAP = 0.10             # a runner-up must be within this of the best match
MAX_HITS = 2           # at most this many candidate techniques per flow (3rd place was noise on real runs)
NO_LOOKUP = {"ANOMALOUS_FLOW"}   # no concrete behaviour found, so no technique lookup


def rollup(hits):
    """Collapse sub-techniques into their parent technique (flows cannot tell Password Spraying from
    Password Guessing). The best sub-technique is kept as the 'closest variant'."""
    best = {}
    for h in hits:
        pid = h["technique_id"].split(".")[0]
        if pid not in best or h["confidence"] > best[pid]["confidence"]:
            best[pid] = h
    out = []
    for pid, h in sorted(best.items(), key=lambda kv: -kv[1]["confidence"]):
        r = dict(h)
        r["technique_id"] = pid
        r["name"] = h["name"].split(": ")[0]
        if "." in h["technique_id"] and ": " in h["name"]:
            r["variant"] = f"{h['technique_id']} {h['name'].split(': ', 1)[1]}"
        out.append(r)
    return out


def select_hits(hits):
    hits = rollup(hits)
    if not hits or hits[0]["confidence"] < MIN_CONF:
        return []
    top = hits[0]["confidence"]
    return [h for h in hits[:MAX_HITS] if h["confidence"] >= MIN_CONF and top - h["confidence"] <= GAP]


def render_log(raw, f, behavior, stats_text, hits, ctx):
    lines = [f"[FASTBRAIN] flow={f['flow_id']} s_score={raw.get('s_score')} route={raw.get('route')}"]
    lines.append(f"[HEURISTIC] flow pattern looks like {behavior} ({stats_text}; inferred, not observed)")
    if not hits:
        why = ("no specific attack behaviour identified, technique lookup skipped" if behavior in NO_LOOKUP
               else f"no technique matched above confidence {MIN_CONF}")
        lines.append(f"[VECTORRAG] {why}")
    for h in hits:
        variant = f" closest variant: {h['variant']}" if h.get("variant") else ""
        lines.append(f"[VECTORRAG] {h['technique_id']} {h['name']} ({h['tactics']}) "
                     f"confidence={h['confidence']}{variant} action={h['action']}")
    lines.append(
        f"[GRAPHRAG] {f['src']}->{f['dst']} authorized_pair={ctx['pair_authorized']} "
        f"baseline_flows={ctx['pair_baseline_flows']} dst_external={ctx['dst_external']} "
        f"unauthorized_edges={ctx['unauthorized_edges_from_src']} "
        f"blast_radius={ctx['blast_radius_hosts']}")
    return "\n".join(lines)


def _rows(path):
    with open(path) as fh:
        for line in fh:
            if line.strip():
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    yield None


def build(scored_path, index, baseline_routes=("CLEAR",), hops=2, baseline_path=None, baseline_label=None):
    """Returns (events, logs {event_id: text}, skipped).

    Baseline source: by default the CLEAR flows in the scored file. That breaks for recurring jobs the
    fast brain finds unusual (a nightly backup never gets cleared, so it never becomes baseline). Pass
    baseline_path (the normal data the fast brain was trained on) and baseline_label (the same
    --normal-label used for training) to build the baseline from that instead."""
    graph, stats, slow, skipped, first_inc = FlowGraph(), SrcStats(), [], 0, {}
    for raw in _rows(scored_path):                       # pass 1: incident flows
        if raw is None:
            skipped += 1
            continue
        f = normalize(raw)
        if not f["src"] or not f["dst"]:
            skipped += 1
            continue
        if raw.get("route") == "SLOW_BRAIN":             # FAST_TRACK bypasses this layer by design
            slow.append((raw, f))
            stats.add(f)
            dt, pair = parse_ts(f["ts"]), (f["src"], f["dst"])
            if dt and (pair not in first_inc or dt < first_inc[pair]):
                first_inc[pair] = dt

    pairs = {(f["src"], f["dst"]) for _, f in slow}
    for raw in _rows(baseline_path or scored_path):      # pass 2: baseline, incident pairs only
        if raw is None:
            continue
        if baseline_path:
            if baseline_label is not None and raw.get("label") != baseline_label:
                continue
        elif raw.get("route") not in baseline_routes:
            continue
        f = normalize(raw)
        pair = (f["src"], f["dst"])
        if pair in pairs:
            graph.add_baseline(*pair, ts=f["ts"], before=first_inc.get(pair))

    prepared = []
    for raw, f in slow:                                  # anomalies join the graph before context queries
        behavior = infer_behavior(f, stats)
        graph.add_anomaly(f["src"], f["dst"], behavior)
        prepared.append((raw, f, behavior))

    events, logs = [], {}
    for i, (raw, f, behavior) in enumerate(prepared):
        hits = [] if behavior in NO_LOOKUP else select_hits(index.query(describe(f, behavior, stats), k=8))
        ev = build_event(f, f"E{i:06d}")
        events.append(ev)
        logs[ev["event_id"]] = render_log(raw, f, behavior, behavior_stats(f, stats), hits, graph.context(f["src"], f["dst"], hops))

    for src, dst in sorted(pairs):
        summ = graph.baseline_summary(src, dst)
        as_of = first_inc.get((src, dst))
        if summ is None or as_of is None:
            continue
        # The summary is a fact "as of" the moment just before the incident, not an old observation.
        # Dating it at the last cleared flow would make a daily job (e.g. 02:00 backup) older than the
        # verifier's 24h max_age and every claim citing it would come back stale. The real first and
        # last dates stay in the log text.
        eid = f"{BASE_PREFIX}{src}-{dst}"
        events.append({"event_id": eid, "ts": (as_of - timedelta(seconds=1)).isoformat(), "rel": "baseline_connect",
                       "src": src, "dst": dst, "source_system": "netflow_baseline",
                       "parse_conf": 1.0, "match_conf": 1.0})
        logs[eid] = (f"[BASELINE] {summ['count']} known normal flows between {src} and {dst}, first seen "
                     f"{summ['first_ts']}, most recent {summ['last_ts']} (summary as of the incident start)")
    events.sort(key=lambda e: (e["ts"], e["event_id"]))
    return events, logs, skipped


def main():
    global MIN_CONF, GAP, MAX_HITS
    ap = argparse.ArgumentParser(description="Write events.jsonl + logs.json for inspection.")
    ap.add_argument("--scored", required=True)
    ap.add_argument("--events", default="events.jsonl")
    ap.add_argument("--logs", default="logs.json")
    ap.add_argument("--chroma-path", default="chroma_db")
    ap.add_argument("--baseline-file", default=None, help="normal flows the fast brain was trained on")
    ap.add_argument("--baseline-label", default=None, help="label that marks normal flows in that file")
    ap.add_argument("--min-conf", type=float, default=MIN_CONF)
    ap.add_argument("--gap", type=float, default=GAP)
    ap.add_argument("--max-hits", type=int, default=MAX_HITS)
    ap.add_argument("--mitre", choices=["seed", "full"], default="full")
    ap.add_argument("--mitre-scope", choices=["network", "flow", "all"], default="network")
    a = ap.parse_args()
    MIN_CONF, GAP, MAX_HITS = a.min_conf, a.gap, a.max_hits
    from .mitre_store import make_index
    events, logs, skipped = build(a.scored, make_index(a.mitre, a.chroma_path, a.mitre_scope),
                                  baseline_path=a.baseline_file, baseline_label=a.baseline_label)
    with open(a.events, "w") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in events)
    with open(a.logs, "w") as fh:
        json.dump(logs, fh, indent=2)
    print(f"{len(events)} events written, {skipped} malformed rows skipped", file=sys.stderr)


if __name__ == "__main__":
    main()
