"""Flow record -> agent layer event (soc_agent.schemas.Event).

What a flow can honestly support: "these two endpoints connected". So every event gets
rel="connect" (the agent's own vocabulary, see soc_agent/patterns.py). Inferred behaviour
(scan, brute force, exfil) is NOT written into rel, because the verifier treats events as
observed evidence and a flow cannot observe a login failure. The inferred label goes into
the log text instead, marked as a heuristic.

parse_conf: 1.0 (deterministic parser); lowered only if the timestamp had to be invented.
match_conf: 1.0, because IPs are used directly as entity names (no entity resolution).
The MITRE similarity score is NOT put here: soc_agent applies a confidence threshold (tau),
and a cosine score of ~0.5 would mark every step low confidence.
"""
from collections import defaultdict
from datetime import datetime, timezone
from .graph_store import is_internal

AUTH_PORTS = {21, 22, 23, 445, 3389}
PORTSCAN_MIN_TARGETS = 15
BRUTE_MIN_REPEATS = 10
EXFIL_MIN_REPEATS = 5
FLOOD_MIN_AVG_PACKETS = 5000   # per flow, averaged over the source host in the batch

REL_PHRASE = {
    "PORT_SCAN": "host probing many ports on several servers with tiny connections",
    "BRUTE_FORCE_SUSPECTED": "repeated failed login attempts against ssh from a single source",
    "EXFIL_SUSPECTED": "internal host sending data out to an external server again and again",
    "DOS_FLOOD_SUSPECTED": "very large burst of packets flooding a single server to exhaust it",
    "ANOMALOUS_FLOW": "unusual network flow with abnormal packet and byte profile",
}


def normalize(flow):
    def g(*keys):
        for k in keys:
            if flow.get(k) not in (None, ""):
                return flow[k]
        return None
    return {"flow_id": g("flow_id"), "ts": g("timestamp", "ts"),
            "src": g("src_ip", "source_ip"), "dst": g("dst_ip", "dest_ip"),
            "dport": g("dst_port"), "proto": g("protocol"),
            "packets": g("packets", "packet_count"), "bytes": g("bytes", "byte_count"),
            "s_score": flow.get("s_score")}


class SrcStats:
    """Per-batch aggregates so one flow can be judged in context of its source."""
    def __init__(self):
        self.targets = defaultdict(set)
        self.n = defaultdict(int)
        self.pkts = defaultdict(float)
        self.pair_n = defaultdict(int)

    def add(self, f):
        self.targets[f["src"]].add((f["dst"], f["dport"]))
        self.n[f["src"]] += 1
        self.pkts[f["src"]] += f["packets"] or 0
        self.pair_n[(f["src"], f["dst"])] += 1


def infer_behavior(f, st):
    s, d = f["src"], f["dst"]
    avg_pkts = st.pkts[s] / max(st.n[s], 1)
    if len(st.targets[s]) >= PORTSCAN_MIN_TARGETS and avg_pkts <= 3:
        return "PORT_SCAN"
    if f["dport"] in AUTH_PORTS and st.pair_n[(s, d)] >= BRUTE_MIN_REPEATS:
        return "BRUTE_FORCE_SUSPECTED"
    if is_internal(s) and not is_internal(d) and st.pair_n[(s, d)] >= EXFIL_MIN_REPEATS:
        return "EXFIL_SUSPECTED"
    if avg_pkts >= FLOOD_MIN_AVG_PACKETS:
        return "DOS_FLOOD_SUSPECTED"
    return "ANOMALOUS_FLOW"


def describe(f, behavior, st):
    """Text for the VectorRAG query: the behaviour phrase only. No IPs and no counts, because
    words like "flows" and "packets per flow" pull every query toward the port scan technique."""
    return REL_PHRASE[behavior]


def behavior_stats(f, st):
    """Batch statistics for the log text (kept out of the retrieval query)."""
    s = f["src"]
    return (f"{st.n[s]} flows from this source in this batch, "
            f"about {st.pkts[s] / max(st.n[s], 1):.0f} packets per flow")


def build_event(f, fallback_id):
    # keep the timestamp as the flow had it (soc_agent/io.py parses RFC3339 and space-separated);
    # the schema needs a ts, so fall back to ingestion time and lower parse_conf
    ts = f["ts"] or datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {"event_id": f["flow_id"] or fallback_id, "ts": ts, "rel": "connect",
            "src": f["src"], "dst": f["dst"], "source_system": "netflow",
            "parse_conf": 1.0 if f["ts"] else 0.85, "match_conf": 1.0}
