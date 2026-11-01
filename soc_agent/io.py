"""Load events from the ingestion layer (JSONL) into an EvidenceStore, and wrap them as a Scenario."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .evidence_store import EvidenceStore
from .models import Alert, Outcome
from .scenarios import Scenario
from .schemas import Event


def _ts(s: str) -> datetime:
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def event_from_dict(d: dict) -> Event:
    return Event(
        event_id=str(d["event_id"]), ts=_ts(d["ts"]), rel=str(d.get("rel") or d["type"]),
        src=str(d["src"]), dst=str(d["dst"]), source_system=str(d.get("source_system", "unknown")),
        parse_conf=float(d.get("parse_conf", 1.0)), match_conf=float(d.get("match_conf", 1.0)),
    )


def load_events_jsonl(path: str) -> EvidenceStore:
    store = EvidenceStore()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                store.add_event(event_from_dict(json.loads(line)))
    return store


def scenario_from_store(store: EvidenceStore, entities: tuple[str, ...], now: datetime | None = None,
                        alert_id: str = "live-alert", logs: dict[str, str] | None = None) -> Scenario:
    """Wrap a real evidence store as a Scenario so the agent can triage it (no ground truth)."""
    if now is None:
        now = max((d["event"].ts for _, _, d in store.g.edges(data=True)), default=datetime.now(timezone.utc))
    return Scenario(
        case_id=alert_id, kind="unknown", template="unknown", store=store,
        alert=Alert(alert_id, now, entities, f"Alert on {', '.join(entities)}"),
        logs=logs or {}, now=now, truth_chain=[], truth_action=None,
        preferred=Outcome.ESCALATE, acceptable=frozenset(Outcome),
    )
