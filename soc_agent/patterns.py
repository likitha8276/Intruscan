"""Attack-chain templates and a tiny subgraph matcher.

Used in three places:
  * the scenario generator (ground-truth incidents are instantiated from templates),
  * the simulated LLM (its stand-in for 'domain knowledge'),
  * the risk gate (a graph-derived severity floor).

`known=False` templates are HELD OUT from the defender's library (the gate), so the
evaluation can show what the gate cannot catch.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from typing import Iterable, Iterator

from .schemas import ChainStep, Event


@dataclass(frozen=True)
class Template:
    name: str
    steps: tuple[tuple[str, str, str], ...]     # (rel, src_role, dst_role)
    action_type: str
    action_role: str
    known: bool = True


TEMPLATES: dict[str, Template] = {t.name: t for t in [
    Template("brute_force_exec",
             (("login_fail", "ip", "host"), ("login_success", "ip", "host"), ("exec", "host", "proc")),
             "isolate_host", "host"),
    Template("phishing_c2",
             (("phish_click", "user", "host"), ("download", "host", "payload"),
              ("exec", "host", "payload"), ("connect", "host", "c2")),
             "block_ip", "c2"),
    Template("lateral_movement",
             (("login_success", "user", "host"), ("remote_exec", "host", "host2"),
              ("file_write", "host2", "tool"), ("connect", "host2", "c2")),
             "isolate_host", "host2"),
    Template("data_exfil",
             (("login_success", "user", "host"), ("file_read", "host", "db"),
              ("archive", "host", "arc"), ("connect", "host", "extip")),
             "disable_account", "user"),
    Template("priv_esc",
             (("login_success", "user", "host"), ("exec", "host", "tool"),
              ("priv_change", "user", "grp")),
             "disable_account", "user"),
    # held out of the defender's pattern library
    Template("ransomware_prep",
             (("login_success", "user", "host"), ("exec", "host", "tool"),
              ("file_write", "host", "note"), ("encrypt", "host", "vol")),
             "isolate_host", "host", known=False),
    Template("webshell",
             (("http_post", "ip", "host"), ("file_write", "host", "shell"),
              ("exec", "host", "shell"), ("connect", "host", "c2")),
             "isolate_host", "host", known=False),
]}

KNOWN_TEMPLATES = [t for t in TEMPLATES.values() if t.known]

# Relations whose presence makes a (partial) chain worth escalating.
HIGH_RISK_RELS = {"exec", "remote_exec", "priv_change", "connect", "encrypt", "archive"}

# Relative risk of a relation, used by the subgraph selector.
REL_RISK = {
    "exec": 0.9, "remote_exec": 0.9, "priv_change": 0.9, "encrypt": 0.9,
    "connect": 0.6, "file_write": 0.5, "login_success": 0.5, "download": 0.5,
    "phish_click": 0.5, "archive": 0.5, "http_post": 0.5, "login_fail": 0.4,
    "file_read": 0.2, "dns_query": 0.1, "http_get": 0.1, "heartbeat": 0.05,
    "login_blocked": 0.4, "exec_blocked": 0.6,
}


def find_bindings(template: Template, events: Iterable[Event],
                  idxs: Iterable[int] | None = None,
                  anchors: set[str] | None = None) -> Iterator[dict[str, str]]:
    """Yield role->entity bindings for the given step subset, optionally anchored."""
    by_rel: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_rel[e.rel].append(e)
    idxs = list(range(len(template.steps))) if idxs is None else list(idxs)

    def rec(i: int, binding: dict[str, str]) -> Iterator[dict[str, str]]:
        if i == len(idxs):
            yield dict(binding)
            return
        rel, sr, dr = template.steps[idxs[i]]
        for e in by_rel.get(rel, ()):
            if sr in binding and binding[sr] != e.src:
                continue
            if dr in binding and binding[dr] != e.dst:
                continue
            nb = dict(binding)
            nb[sr], nb[dr] = e.src, e.dst
            yield from rec(i + 1, nb)

    for b in rec(0, {}):
        if anchors is None or any(v in anchors for v in b.values()):
            yield b


def chain_from(template: Template, idxs: Iterable[int], binding: dict[str, str],
               invent=None) -> list[ChainStep]:
    """Instantiate chain steps; `invent(role)` supplies names for unbound roles."""
    out = []
    for i in idxs:
        rel, sr, dr = template.steps[i]
        src = binding.get(sr) or (invent(sr) if invent else sr)
        dst = binding.get(dr) or (invent(dr) if invent else dr)
        out.append(ChainStep(rel, src, dst))
    return out


def best_partial(template: Template, events: list[Event], anchors: set[str],
                 min_size: int = 2) -> tuple[tuple[int, ...], dict[str, str]] | None:
    """Largest step subset (>= min_size) that binds consistently on the given events."""
    n = len(template.steps)
    for size in range(n, min_size - 1, -1):
        for subset in combinations(range(n), size):
            b = next(find_bindings(template, events, subset, anchors), None)
            if b is not None:
                return subset, b
    return None
