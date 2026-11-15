"""Incident records shared by every route, and their SQLite store.

One record format covers all three outcomes so a dashboard (or any other consumer) needs a
single reader:

* ``fast_track``  - a FAST_TRACK flow, recorded as a HIGH-priority incident with NO LLM call;
* ``slow_brain``  - a per-source incident analysed by the Layer 4 agent (``soc_result`` holds
                    its verbatim output);
* ``untimed``     - a SLOW_BRAIN flow whose timestamp is missing or surrogate. The verifier
                    depends on real event time, so these are escalated to an analyst without
                    an LLM call instead of being verified against an invented time.

The store is separate from the Go ingester's ``forensics_archive.db`` (which Go owns).
Records are unsigned: see docs/SECURITY_AND_LIMITATIONS.md ("Provenance").
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

RECORD_VERSION = 1

KIND_FAST_TRACK = "fast_track"
KIND_SLOW_BRAIN = "slow_brain"
KIND_UNTIMED = "untimed"

PRIORITY_HIGH = "HIGH"
PRIORITY_MEDIUM = "MEDIUM"

DISP_FAST_TRACK = "FAST_TRACK_RECORDED"
DISP_UNTIMED = "UNTIMED_ESCALATED"
DISP_PROPOSE = "SLOW_BRAIN_PROPOSE"
DISP_ESCALATE = "SLOW_BRAIN_ESCALATE"
DISP_CLOSE = "SLOW_BRAIN_CLOSE"
DISP_ERROR = "SLOW_BRAIN_ERROR"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id   TEXT PRIMARY KEY,
    record_version INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    recorded_at   TEXT NOT NULL,
    priority      TEXT NOT NULL,
    disposition   TEXT NOT NULL,
    llm_called    INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'open',
    src           TEXT,
    dst           TEXT,
    route         TEXT,
    s_score       REAL,
    first_flow_ts TEXT,
    ts_kind       TEXT,
    ts_original   TEXT,
    flow_ids      TEXT NOT NULL,
    reasons       TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    mitre         TEXT NOT NULL,
    soc_result    TEXT,
    model_sha256  TEXT,
    feature_set   TEXT,
    thresholds    TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_kind ON incidents(kind);
CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority);
CREATE INDEX IF NOT EXISTS idx_incidents_src ON incidents(src);
"""

_JSON_COLUMNS = ("flow_ids", "reasons", "evidence", "mitre", "soc_result", "thresholds")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(*parts: object) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode("utf-8")).hexdigest()[:16]


@dataclass
class Incident:
    incident_id: str
    kind: str
    priority: str
    disposition: str
    llm_called: bool
    flow_ids: list[str]
    reasons: list[str]
    recorded_at: str = field(default_factory=utc_now)
    status: str = "open"
    src: str | None = None
    dst: str | None = None
    route: str | None = None
    s_score: float | None = None
    first_flow_ts: str | None = None
    ts_kind: str | None = None
    ts_original: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    mitre: list[dict[str, Any]] = field(default_factory=list)
    soc_result: dict[str, Any] | None = None
    model_sha256: str | None = None
    feature_set: str | None = None
    thresholds: dict[str, Any] | None = None
    record_version: int = RECORD_VERSION

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _flow_ts_fields(flow: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
    stamp = flow.get("timestamp", flow.get("ts"))
    return (
        str(stamp) if stamp not in (None, "") else None,
        str(flow.get("ts_kind") or ("absolute" if stamp else "missing")),
        None if flow.get("ts_original") in (None, "") else str(flow["ts_original"]),
    )


def _src_dst(flow: Mapping[str, Any]) -> tuple[str | None, str | None]:
    src = flow.get("src_ip", flow.get("source_ip"))
    dst = flow.get("dst_ip", flow.get("dest_ip"))
    return (None if src is None else str(src), None if dst is None else str(dst))


def fast_track_incident(
    flow: Mapping[str, Any],
    *,
    model_sha256: str | None = None,
    feature_set: str | None = None,
    thresholds: Mapping[str, Any] | None = None,
) -> Incident:
    """HIGH-priority incident for one FAST_TRACK flow. No LLM is involved, by design."""
    if flow.get("route") != "FAST_TRACK":
        raise ValueError(f"flow route is {flow.get('route')!r}, expected 'FAST_TRACK'")
    flow_id = flow.get("flow_id")
    if not isinstance(flow_id, str) or not flow_id.strip():
        raise ValueError("flow_id must be a non-empty string")
    score = flow.get("s_score")
    ts, ts_kind, ts_original = _flow_ts_fields(flow)
    src, dst = _src_dst(flow)
    reasons = ["fast_brain_score_above_upper_threshold", "no_llm_call_by_design"]
    if ts_kind != "absolute":
        reasons.append(f"timestamp_{ts_kind}")
    return Incident(
        incident_id=f"FT-{_digest('fast_track', flow_id)}",
        kind=KIND_FAST_TRACK,
        priority=PRIORITY_HIGH,
        disposition=DISP_FAST_TRACK,
        llm_called=False,
        flow_ids=[flow_id],
        reasons=reasons,
        src=src,
        dst=dst,
        route="FAST_TRACK",
        s_score=None if score is None else float(score),
        first_flow_ts=ts,
        ts_kind=ts_kind,
        ts_original=ts_original,
        evidence={"flows": [dict(flow)]},
        mitre=[],
        model_sha256=model_sha256,
        feature_set=feature_set,
        thresholds=None if thresholds is None else dict(thresholds),
    )


def untimed_incident(
    flow: Mapping[str, Any],
    *,
    model_sha256: str | None = None,
    feature_set: str | None = None,
    thresholds: Mapping[str, Any] | None = None,
) -> Incident:
    """A SLOW_BRAIN flow that cannot be verified because its timestamp is not real event time."""
    flow_id = flow.get("flow_id")
    if not isinstance(flow_id, str) or not flow_id.strip():
        raise ValueError("flow_id must be a non-empty string")
    score = flow.get("s_score")
    ts, ts_kind, ts_original = _flow_ts_fields(flow)
    src, dst = _src_dst(flow)
    return Incident(
        incident_id=f"UT-{_digest('untimed', flow_id)}",
        kind=KIND_UNTIMED,
        priority=PRIORITY_MEDIUM,
        disposition=DISP_UNTIMED,
        llm_called=False,
        flow_ids=[flow_id],
        reasons=[
            f"timestamp_{ts_kind}_excluded_from_verifier",
            "analyst_review_required",
            "no_llm_call",
        ],
        src=src,
        dst=dst,
        route=str(flow.get("route") or "SLOW_BRAIN"),
        s_score=None if score is None else float(score),
        first_flow_ts=ts,
        ts_kind=ts_kind,
        ts_original=ts_original,
        evidence={"flows": [dict(flow)]},
        mitre=[],
        model_sha256=model_sha256,
        feature_set=feature_set,
        thresholds=None if thresholds is None else dict(thresholds),
    )


def _disposition_for(soc_result: Mapping[str, Any]) -> str:
    outcome = soc_result.get("outcome")
    return {
        "PROPOSE": DISP_PROPOSE,
        "ESCALATE": DISP_ESCALATE,
        "CLOSE": DISP_CLOSE,
    }.get(str(outcome), DISP_ERROR)


def slow_brain_incident(
    *,
    src: str,
    events: Iterable[Mapping[str, Any]],
    logs: Mapping[str, str],
    soc_result: Mapping[str, Any],
    mitre: Iterable[Mapping[str, Any]] = (),
    flows: Iterable[Mapping[str, Any]] = (),
    model_sha256: str | None = None,
    feature_set: str | None = None,
    thresholds: Mapping[str, Any] | None = None,
) -> Incident:
    """Incident for one source host analysed by the Layer 4 agent (verbatim ``soc_result``)."""
    event_list = [dict(e) for e in events]
    flow_ids = [str(e["event_id"]) for e in event_list if not str(e["event_id"]).startswith("BASE-")]
    disposition = _disposition_for(soc_result)
    if disposition == DISP_PROPOSE:
        priority = PRIORITY_HIGH
    elif disposition == DISP_ESCALATE:
        priority = PRIORITY_MEDIUM
    elif disposition == DISP_CLOSE:
        priority = "LOW"
    else:
        priority = PRIORITY_MEDIUM  # an analysis that failed is never treated as benign
    flow_list = [dict(f) for f in flows]
    scores = [f["s_score"] for f in flow_list if isinstance(f.get("s_score"), (int, float))]
    stamps = sorted(str(e["ts"]) for e in event_list if e.get("ts"))
    return Incident(
        incident_id=f"SB-{_digest('slow_brain', src, *sorted(flow_ids))}",
        kind=KIND_SLOW_BRAIN,
        priority=priority,
        disposition=disposition,
        llm_called=soc_result.get("status") not in (None, "CLI_ERROR", "INVALID_FLOW"),
        flow_ids=flow_ids,
        reasons=[str(r) for r in soc_result.get("reasons", [])],
        src=src,
        route="SLOW_BRAIN",
        s_score=max(scores) if scores else None,
        first_flow_ts=stamps[0] if stamps else None,
        ts_kind="absolute",
        evidence={"events": event_list, "logs": {k: v for k, v in logs.items() if k in {e["event_id"] for e in event_list}}},
        mitre=[dict(m) for m in mitre],
        soc_result=dict(soc_result),
        model_sha256=model_sha256,
        feature_set=feature_set,
        thresholds=None if thresholds is None else dict(thresholds),
    )


class IncidentStore:
    """SQLite-backed incident table (stdlib only)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def save(self, incident: Incident, *, replace: bool = False) -> bool:
        """Insert an incident. Returns True if a row was written.

        Fast-track and untimed records are idempotent (``replace=False``: an existing id is
        left untouched). Slow Brain records pass ``replace=True`` so a re-analysis supersedes.
        """
        row = incident.to_dict()
        row["llm_called"] = int(row["llm_called"])
        for column in _JSON_COLUMNS:
            row[column] = None if row[column] is None else json.dumps(row[column], allow_nan=False, default=str)
        columns = list(row)
        verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        sql = f"{verb} INTO incidents ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(sql, [row[c] for c in columns])
            return cursor.rowcount == 1

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        for column in _JSON_COLUMNS:
            if data.get(column) is not None:
                data[column] = json.loads(data[column])
        data["llm_called"] = bool(data["llm_called"])
        return data

    def get(self, incident_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return None if row is None else self._decode(row)

    def list(self, *, kind: str | None = None, priority: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        clauses, params = [], []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if priority:
            clauses.append("priority = ?")
            params.append(priority)
        sql = "SELECT * FROM incidents"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY recorded_at DESC, incident_id"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        with closing(self._connect()) as conn:
            return [self._decode(r) for r in conn.execute(sql, params)]

    def counts(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        with closing(self._connect()) as conn:
            for column in ("kind", "priority", "disposition", "status"):
                out[column] = {
                    r[0]: r[1] for r in conn.execute(f"SELECT {column}, COUNT(*) FROM incidents GROUP BY {column}")
                }
        return out


def run_context_from_model(model_path: str | Path, thresholds_path: str | Path | None = None) -> dict[str, Any]:
    """Model identity for incident records: fingerprint, feature set and thresholds in force.

    Loads the model with joblib (pickle): only pass a model file you trust.
    """
    import joblib

    from .fast_brain import EarlyExitMVIForest
    from .thresholds import model_fingerprint, resolve_routing_thresholds

    forest = joblib.load(model_path)
    if not isinstance(forest, EarlyExitMVIForest):
        raise ValueError("model file does not contain an EarlyExitMVIForest")
    routing = resolve_routing_thresholds(thresholds_path, model_path)
    return {
        "model_sha256": model_fingerprint(model_path),
        "feature_set": forest.feature_set,
        "thresholds": {"lower": routing.lower, "upper": routing.upper, "source": routing.source},
    }


def record_scored_file(
    scored_path: str | Path,
    store: IncidentStore,
    context: Mapping[str, Any] | None = None,
    *,
    include_untimed: bool = True,
) -> dict[str, int]:
    """Record FAST_TRACK flows (and, optionally, untimed SLOW_BRAIN flows) from a scored JSONL.

    FAST_TRACK flows become HIGH-priority incidents with no LLM call. Re-running is idempotent.
    Returns counts: fast_track, untimed, existing (already recorded), invalid.
    """
    ctx = dict(context or {})
    counts = {"fast_track": 0, "untimed": 0, "existing": 0, "invalid": 0}
    with open(scored_path, encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            try:
                flow = json.loads(line)
                if not isinstance(flow, dict):
                    raise ValueError("row is not an object")
                route = flow.get("route")
                if route == "FAST_TRACK":
                    incident, key = fast_track_incident(flow, **ctx), "fast_track"
                elif include_untimed and route == "SLOW_BRAIN" and flow.get("ts_kind", "absolute") != "absolute":
                    incident, key = untimed_incident(flow, **ctx), "untimed"
                else:
                    continue
            except (json.JSONDecodeError, ValueError):
                counts["invalid"] += 1
                continue
            if store.save(incident):
                counts[key] += 1
            else:
                counts["existing"] += 1
    return counts
