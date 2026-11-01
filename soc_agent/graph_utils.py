"""Helpers over the NetworkX-backed evidence store (so the store class stays untouched)."""
from __future__ import annotations

from .schemas import Event


def all_events(store) -> list[Event]:
    out = [d["event"] for _, _, d in store.g.edges(data=True)]
    return sorted(out, key=lambda e: (e.ts, e.event_id))


def entity_events(store, entity: str) -> list[Event]:
    """Events where `entity` is the source or destination."""
    g = store.g
    out: list[Event] = []
    if entity not in g:
        return out
    for _, _, d in g.out_edges(entity, data=True):
        out.append(d["event"])
    for _, _, d in g.in_edges(entity, data=True):
        out.append(d["event"])
    return out


def neighbors(store, entity: str) -> set[str]:
    g = store.g
    if entity not in g:
        return set()
    return set(g.successors(entity)) | set(g.predecessors(entity))
