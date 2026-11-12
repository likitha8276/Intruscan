"""Layer 3b: GraphRAG over host relationships (NetworkX, in memory).

Baseline edges come from flows the fast brain CLEARED (or benign labelled
training flows). An edge seen >= min_support times in baseline counts as an
authorized pair. Anomalous edges are added on top and used for blast radius.
"""
import ipaddress
from datetime import datetime, timezone
import networkx as nx


def parse_ts(value):
    """Same parsing rule as soc_agent/io.py (RFC3339 or space separated, naive = UTC)."""
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


class FlowGraph:
    def __init__(self, min_support=3):
        self.g = nx.DiGraph()
        self.min_support = min_support

    def _edge(self, s, d):
        if not self.g.has_edge(s, d):
            self.g.add_edge(s, d, baseline_count=0, anomalous_count=0, rels=set(),
                            baseline_first=None, baseline_last=None, baseline_last_any=None)
        return self.g[s][d]

    def add_baseline(self, s, d, ts=None, before=None):
        """Count a cleared flow. baseline_last only uses flows older than `before`
        (the pair's earliest incident flow) so the summary event never post-dates it."""
        e = self._edge(s, d)
        e["baseline_count"] += 1
        dt = parse_ts(ts)
        if dt is None:
            return
        if e["baseline_last_any"] is None or dt > e["baseline_last_any"][0]:
            e["baseline_last_any"] = (dt, ts)
        if e["baseline_first"] is None or dt < e["baseline_first"][0]:
            e["baseline_first"] = (dt, ts)
        if (before is None or dt < before) and (e["baseline_last"] is None or dt > e["baseline_last"][0]):
            e["baseline_last"] = (dt, ts)

    def baseline_summary(self, s, d):
        if not self.is_authorized(s, d):
            return None
        e = self.g[s][d]
        last = e["baseline_last"] or e["baseline_last_any"]
        if e["baseline_first"] is None or last is None:
            return None
        return {"count": e["baseline_count"], "first_ts": e["baseline_first"][1], "last_ts": last[1]}

    def add_anomaly(self, s, d, rel):
        e = self._edge(s, d)
        e["anomalous_count"] += 1
        e["rels"].add(rel)

    def is_authorized(self, s, d):
        return self.g.has_edge(s, d) and self.g[s][d]["baseline_count"] >= self.min_support

    def anomaly_view(self):
        edges = [(u, v) for u, v, e in self.g.edges(data=True) if e["anomalous_count"] > 0]
        return self.g.edge_subgraph(edges)

    def has_path(self, a, b):
        """For verifier.py: does a claimed path exist in the graph?"""
        return a in self.g and b in self.g and nx.has_path(self.g, a, b)

    def context(self, src, dst, hops=2):
        view = self.anomaly_view()
        reach = {}
        if src in view:
            reach = nx.single_source_shortest_path_length(view, src, cutoff=hops)
            reach.pop(src, None)
        unauthorized = sorted(
            d for _, d, e in self.g.out_edges(src, data=True)
            if e["anomalous_count"] > 0 and e["baseline_count"] < self.min_support
        ) if src in self.g else []
        base = self.g[src][dst]["baseline_count"] if self.g.has_edge(src, dst) else 0
        return {
            "pair_authorized": self.is_authorized(src, dst),
            "pair_baseline_flows": base,
            "dst_external": not is_internal(dst),
            "unauthorized_edges_from_src": unauthorized[:10],
            "unauthorized_edge_count": len(unauthorized),
            "blast_radius_hosts": sorted(reach)[:10],
            "blast_radius_size": len(reach),
        }
