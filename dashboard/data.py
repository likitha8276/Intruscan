"""Read-only data access for the SOC dashboard.

Everything here reads the project's real outputs: the scored-flow JSONL written by
``soc_agent.fast_brain_cli score`` and the incident store written by the handoff tools
(``soc_agent.incidents``). Missing files give empty results, never invented ones.
"""

from __future__ import annotations

import json
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd

from soc_agent.incidents import IncidentStore

ROUTES = ("CLEAR", "SLOW_BRAIN", "FAST_TRACK")


@dataclass
class LoadedFlows:
    frame: pd.DataFrame
    invalid_rows: int
    truncated: bool


def load_scored_flows(path: str | Path | None, max_rows: int = 200_000) -> LoadedFlows:
    """Load a scored JSONL (most recent ``max_rows`` rows if larger). Missing file -> empty."""
    if not path or not Path(path).is_file():
        return LoadedFlows(pd.DataFrame(), 0, False)
    rows: deque[dict[str, Any]] = deque(maxlen=max_rows)
    invalid = 0
    total = 0
    with open(path, encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            total += 1
            try:
                row = json.loads(line)
                if not isinstance(row, dict) or "route" not in row:
                    raise ValueError("not a scored flow")
            except (json.JSONDecodeError, ValueError):
                invalid += 1
                continue
            rows.append(row)
    return LoadedFlows(pd.DataFrame(list(rows)), invalid, total - invalid > max_rows)


def route_counts(frame: pd.DataFrame) -> dict[str, int]:
    counts = Counter(frame["route"]) if "route" in frame else Counter()
    return {route: int(counts.get(route, 0)) for route in ROUTES}


def traffic_split(frame: pd.DataFrame) -> dict[str, int]:
    """Predicted benign (CLEAR) vs suspicious (SLOW_BRAIN or FAST_TRACK). This is the model's
    routing, not ground truth: a suspicious route is not a confirmed attack."""
    counts = route_counts(frame)
    return {
        "benign (CLEAR)": counts["CLEAR"],
        "suspicious (SLOW_BRAIN + FAST_TRACK)": counts["SLOW_BRAIN"] + counts["FAST_TRACK"],
    }


def label_vs_route(frame: pd.DataFrame) -> pd.DataFrame:
    """Crosstab of the dataset's own label against the route (only if flows carry labels)."""
    if frame.empty or "label" not in frame or "route" not in frame:
        return pd.DataFrame()
    return pd.crosstab(frame["label"], frame["route"]).reindex(columns=list(ROUTES), fill_value=0)


def timestamp_quality(frame: pd.DataFrame) -> dict[str, int]:
    if frame.empty:
        return {}
    kinds = frame["ts_kind"].fillna("absolute") if "ts_kind" in frame else pd.Series("absolute", index=frame.index)
    return {str(k): int(v) for k, v in kinds.value_counts().items()}


def _col(frame: pd.DataFrame, *names: str) -> str | None:
    return next((n for n in names if n in frame), None)


def host_graph(frame: pd.DataFrame, routes: tuple[str, ...] = ("SLOW_BRAIN", "FAST_TRACK"), max_edges: int = 200) -> nx.DiGraph:
    """Directed host graph of non-CLEAR flows; edge attributes aggregate what was observed."""
    graph = nx.DiGraph()
    if frame.empty or "route" not in frame:
        return graph
    src_col = _col(frame, "src_ip", "source_ip")
    dst_col = _col(frame, "dst_ip", "dest_ip")
    if not src_col or not dst_col:
        return graph
    subset = frame[frame["route"].isin(routes)]
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for row in subset.itertuples(index=False):
        d = row._asdict()
        key = (str(d[src_col]), str(d[dst_col]))
        e = edges.setdefault(key, {"flows": 0, "max_score": 0.0, "fast_track": False})
        e["flows"] += 1
        score = d.get("s_score")
        if isinstance(score, (int, float)) and score == score:
            e["max_score"] = max(e["max_score"], float(score))
        e["fast_track"] = e["fast_track"] or d.get("route") == "FAST_TRACK"
    for (s, t), attrs in sorted(edges.items(), key=lambda kv: -kv[1]["flows"])[:max_edges]:
        graph.add_edge(s, t, **attrs)
    return graph


def incidents_frame(store: IncidentStore | None) -> pd.DataFrame:
    if store is None:
        return pd.DataFrame()
    rows = store.list()
    if not rows:
        return pd.DataFrame()
    frame = pd.DataFrame(rows)
    frame["flow_count"] = frame["flow_ids"].map(len)
    frame["recorded_at"] = pd.to_datetime(frame["recorded_at"], utc=True, errors="coerce")
    return frame


def mitre_summary(incidents: list[dict[str, Any]]) -> pd.DataFrame:
    """ATT&CK technique candidates retrieved by VectorRAG, aggregated across incidents.

    These are similarity-ranked candidates, not verdicts (see rag/README.md)."""
    agg: dict[str, dict[str, Any]] = {}
    for incident in incidents:
        seen: set[str] = set()
        for hit in incident.get("mitre") or []:
            tid = hit.get("technique_id")
            if not tid:
                continue
            e = agg.setdefault(tid, {"technique_id": tid, "name": hit.get("name", ""), "tactics": hit.get("tactics", ""),
                                     "incidents": 0, "max_confidence": 0.0})
            if tid not in seen:
                e["incidents"] += 1
                seen.add(tid)
            e["max_confidence"] = max(e["max_confidence"], float(hit.get("confidence", 0.0)))
    if not agg:
        return pd.DataFrame(columns=["technique_id", "name", "tactics", "incidents", "max_confidence"])
    return pd.DataFrame(sorted(agg.values(), key=lambda r: (-r["incidents"], -r["max_confidence"])))
