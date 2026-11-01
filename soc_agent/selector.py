"""Risk-ranked, token-budgeted subgraph selection for the local model's context."""
from __future__ import annotations

from datetime import datetime

from .graph_utils import all_events, entity_events, neighbors
from .models import Alert
from .patterns import REL_RISK
from .schemas import Event


def render_event(ev: Event) -> str:
    return f"[{ev.event_id}] {ev.ts.isoformat()} {ev.rel} {ev.src} -> {ev.dst} (src={ev.source_system})"


def est_tokens(text: str) -> int:
    return len(text) // 4 + 1


def select_subgraph(store, alert: Alert, now: datetime, budget_tokens: int = 1200,
                    hops: int = 2) -> list[Event]:
    """k-hop neighbourhood of the alert entities, ranked by risk x recency x proximity.

    Returns events in chronological order, within the token budget.
    """
    frontier = set(alert.entities)
    seen = set(frontier)
    dist = {e: 0 for e in frontier}
    for h in range(1, hops + 1):
        nxt = set()
        for ent in frontier:
            for nb in neighbors(store, ent):
                if nb not in seen:
                    seen.add(nb)
                    dist[nb] = h
                    nxt.add(nb)
        frontier = nxt

    cand: dict[str, Event] = {}
    for ent in seen:
        for ev in entity_events(store, ent):
            cand[ev.event_id] = ev

    def score(ev: Event) -> float:
        age_h = max((now - ev.ts).total_seconds() / 3600.0, 0.0)
        recency = 1.0 / (1.0 + age_h / 6.0)
        prox = 1.0 / (1.0 + min(dist.get(ev.src, hops + 1), dist.get(ev.dst, hops + 1)))
        return REL_RISK.get(ev.rel, 0.3) * (0.5 + 0.5 * recency) * (0.5 + 0.5 * prox)

    ranked = sorted(cand.values(), key=lambda e: (-score(e), e.event_id))
    chosen, used = [], 0
    for ev in ranked:
        t = est_tokens(render_event(ev))
        if used + t > budget_tokens:
            continue
        chosen.append(ev)
        used += t
    return sorted(chosen, key=lambda e: (e.ts, e.event_id))


def full_context(store) -> list[Event]:
    """No-selector baseline: every event, chronological."""
    return all_events(store)
