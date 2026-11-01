"""Evidence graph interface.

The verifier only depends on `EvidenceStore.find`. Your teammate's GraphRAG
layer can implement the same two methods, or subclass this one.
"""
from __future__ import annotations

from typing import Protocol

import networkx as nx

from .schemas import ChainStep, Event


class EvidenceReader(Protocol):
    def find(self, rel: str, src: str, dst: str) -> list[Event]: ...


class EvidenceStore:
    """NetworkX MultiDiGraph where each edge carries a full Event."""

    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()

    def add_event(self, ev: Event) -> None:
        self.g.add_edge(ev.src, ev.dst, key=ev.event_id, event=ev, rel=ev.rel, ts=ev.ts)

    def remove_event(self, event_id: str) -> None:
        """Used by the poisoning mutators to delete a true edge."""
        for u, v, k in list(self.g.edges(keys=True)):
            if k == event_id:
                self.g.remove_edge(u, v, key=k)

    def find(self, rel: str, src: str, dst: str) -> list[Event]:
        if not self.g.has_edge(src, dst):
            return []
        out = [d["event"] for d in self.g.get_edge_data(src, dst).values() if d["rel"] == rel]
        return sorted(out, key=lambda e: e.ts)

    def find_step(self, step: ChainStep) -> list[Event]:
        return self.find(step.rel, step.src, step.dst)

    def copy(self) -> "EvidenceStore":
        new = EvidenceStore()
        new.g = self.g.copy()
        return new
