"""Synthetic SOC scenarios with ground truth.

A Scenario bundles: the evidence graph, raw log lines, the alert, the ground-truth
chain/action, and the *acceptable* decisions used for scoring.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

from .evidence_store import EvidenceStore
from .models import Action, Alert, Outcome
from .patterns import TEMPLATES, Template
from .schemas import ChainStep, Event
from .provenance import sign_event
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)

BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/119.0",
    "curl/8.4.0", "python-requests/2.31.0",
]

SRC = {
    "exec": "edr", "remote_exec": "edr", "file_write": "edr", "file_read": "edr", "archive": "edr",
    "encrypt": "edr", "priv_change": "edr", "download": "edr", "heartbeat": "edr",
    "login_fail": "auth", "login_success": "auth",
    "connect": "netflow", "dns_query": "netflow", "http_get": "netflow", "http_post": "netflow",
    "phish_click": "email_gw",
}
ALT_SRC = {"edr": "siem", "auth": "siem", "netflow": "fw", "email_gw": "siem"}

ROLE_KIND = {
    "ip": "ext_ip", "c2": "ext_ip", "extip": "ext_ip", "host": "host", "host2": "host",
    "user": "user", "proc": "proc", "payload": "file", "tool": "file", "shell": "file",
    "db": "db", "arc": "arc", "grp": "grp", "note": "note", "vol": "vol",
}
PROCS = ["powershell.exe", "cmd.exe", "wmic.exe", "rundll32.exe", "mshta.exe", "certutil.exe"]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
GROUPS = ["Domain_Admins", "Administrators", "Backup_Operators"]

LOW_RISK_HOST_RELS = ["dns_query", "http_get", "heartbeat"]


@dataclass
class Scenario:
    case_id: str
    kind: str                                   # incident | benign
    template: str                               # template name, or "benign"
    store: EvidenceStore
    alert: Alert
    logs: dict[str, str]
    now: datetime
    truth_chain: list[ChainStep]
    truth_action: Action | None
    preferred: Outcome
    acceptable: frozenset[Outcome]
    step_event_ids: list[list[str]] = field(default_factory=list)
    family: str = "clean"
    meta: dict = field(default_factory=dict)

    def clone(self) -> "Scenario":
        return replace(self, store=self.store.copy(), logs=dict(self.logs),
                       step_event_ids=[list(s) for s in self.step_event_ids],
                       meta={k: (dict(v) if isinstance(v, dict) else v) for k, v in self.meta.items()})

    @property
    def template_known(self) -> bool:
        t = TEMPLATES.get(self.template)
        return bool(t and t.known)


# ---------------------------------------------------------------- naming helpers

def _name(rng: random.Random, role: str, used: set[str]) -> str:
    kind = ROLE_KIND.get(role, "file")
    for _ in range(50):
        if kind == "host":
            n = f"host-{rng.randint(1, 400):03d}"
        elif kind == "user":
            n = f"user-{rng.choice(USERS)}{rng.randint(1, 99)}"
        elif kind == "ext_ip":
            n = f"{rng.choice(['203.0.113', '198.51.100'])}.{rng.randint(1, 254)}"
        elif kind == "proc":
            n = rng.choice(PROCS)
        elif kind == "db":
            n = f"db-{rng.randint(1, 60)}"
        elif kind == "arc":
            n = f"archive{rng.randint(1, 999)}.zip"
        elif kind == "grp":
            n = rng.choice(GROUPS)
        elif kind == "note":
            n = f"README_{rng.randint(1, 999)}.txt"
        elif kind == "vol":
            n = f"vol-{rng.randint(1, 30)}"
        else:
            n = f"tool{rng.randint(1, 999)}.bin"
        if n not in used:
            used.add(n)
            return n
    raise RuntimeError("could not generate unique name")


def fresh_binding(rng: random.Random, template: Template) -> dict[str, str]:
    used: set[str] = set()
    roles: list[str] = []
    for _, sr, dr in template.steps:
        for r in (sr, dr):
            if r not in roles:
                roles.append(r)
    return {r: _name(rng, r, used) for r in roles}


def log_line(ev: Event, ua: str) -> str:
    return f'LOG| {ev.ts.isoformat()} [{ev.event_id}] {ev.rel} src={ev.src} dst={ev.dst} ua="{ua}"'


def make_event(rng: random.Random, eid: str, ts: datetime, rel: str, src: str, dst: str,
               source: str | None = None, lo: float = 0.90, hi: float = 1.0) -> Event:
    return Event(eid, ts, rel, src, dst, source or SRC.get(rel, "edr"),
                 round(rng.uniform(lo, hi), 3), round(rng.uniform(lo, hi), 3))


def add_with_log(scn: Scenario, rng: random.Random, ev: Event, with_log: bool = True) -> None:
    key = b"soc-agent-benchmark-key"
    signed_ev = replace(ev, provenance_signature=sign_event(ev, key))
    scn.store.add_event(signed_ev)
    if with_log:
        scn.logs[signed_ev.event_id] = log_line(signed_ev, rng.choice(BENIGN_UAS))
# ---------------------------------------------------------------- noise

def add_noise(scn: Scenario, rng: random.Random, n: int, alert_host: str) -> None:
    for i in range(n):
        ts = scn.now - timedelta(minutes=rng.uniform(5, 20 * 60))
        eid = f"{scn.case_id}-n{i}"
        if rng.random() < 0.4:
            rel = rng.choice(LOW_RISK_HOST_RELS)
            dst = {"dns_query": "resolver-1", "http_get": f"site{rng.randint(1, 50)}.example",
                   "heartbeat": "mgmt-1"}[rel]
            ev = make_event(rng, eid, ts, rel, alert_host, dst)
        else:
            other = f"host-{rng.randint(401, 480):03d}"
            rel = rng.choice(["dns_query", "http_get", "heartbeat", "file_read", "login_success"])
            if rel == "login_success":
                ev = make_event(rng, eid, ts, rel, f"user-{rng.choice(USERS)}{rng.randint(1, 99)}", other)
            elif rel == "file_read":
                ev = make_event(rng, eid, ts, rel, other, f"db-{rng.randint(1, 60)}")
            else:
                ev = make_event(rng, eid, ts, rel, other, f"site{rng.randint(1, 50)}.example")
        add_with_log(scn, rng, ev)


# ---------------------------------------------------------------- scenario builders

def _chain_events(rng: random.Random, scn: Scenario, template: Template, binding: dict[str, str],
                  n_steps: int | None = None, corroborate_p: float = 0.85) -> None:
    t0 = scn.now - timedelta(minutes=70)
    for i, (rel, sr, dr) in enumerate(template.steps[: n_steps or len(template.steps)]):
        ts = t0 + timedelta(minutes=i * 8 + rng.uniform(0, 3))
        ids = []
        prim = make_event(rng, f"{scn.case_id}-s{i}a", ts, rel, binding[sr], binding[dr])
        add_with_log(scn, rng, prim)
        ids.append(prim.event_id)
        if rng.random() < corroborate_p:
            alt = make_event(rng, f"{scn.case_id}-s{i}b", ts + timedelta(seconds=rng.uniform(1, 20)),
                             rel, binding[sr], binding[dr], source=ALT_SRC[SRC[rel]])
            add_with_log(scn, rng, alt, with_log=False)
            ids.append(alt.event_id)
        scn.step_event_ids.append(ids)


def new_incident(rng: random.Random, case_id: str, template_name: str, n_noise: int = 25) -> Scenario:
    t = TEMPLATES[template_name]
    b = fresh_binding(rng, t)
    host = b["host"]
    scn = Scenario(
        case_id=case_id, kind="incident", template=template_name, store=EvidenceStore(),
        alert=Alert(case_id, NOW, (host,), f"EDR alert: suspicious activity on {host}"),
        logs={}, now=NOW,
        truth_chain=[ChainStep(r, b[s], b[d]) for r, s, d in t.steps],
        truth_action=Action(t.action_type, b[t.action_role]),
        preferred=Outcome.PROPOSE, acceptable=frozenset({Outcome.PROPOSE, Outcome.ESCALATE}),
        meta={"binding": b},
    )
    _chain_events(rng, scn, t, b)
    add_noise(scn, rng, n_noise, host)
    return scn


HARDNEG_TEMPLATES = ["brute_force_exec", "data_exfil", "phishing_c2"]


def new_benign(rng: random.Random, case_id: str, hardneg: bool = False, n_noise: int = 25) -> Scenario:
    host = f"host-{rng.randint(1, 400):03d}"
    scn = Scenario(
        case_id=case_id, kind="benign", template="benign", store=EvidenceStore(),
        alert=Alert(case_id, NOW, (host,), f"EDR alert: anomalous activity on {host}"),
        logs={}, now=NOW, truth_chain=[], truth_action=None,
        preferred=Outcome.CLOSE, acceptable=frozenset({Outcome.CLOSE, Outcome.ESCALATE}),
        meta={},
    )
    if hardneg:
        t = TEMPLATES[rng.choice(HARDNEG_TEMPLATES)]
        b = fresh_binding(rng, t)
        b["host"] = host
        _chain_events(rng, scn, t, b, n_steps=2)
        scn.meta["hardneg_template"] = t.name
    add_noise(scn, rng, n_noise, host)
    return scn


# ---------------------------------------------------------------- event surgery helpers

def find_event(scn: Scenario, eid: str) -> Event | None:
    for _, _, k, d in scn.store.g.edges(keys=True, data=True):
        if k == eid:
            return d["event"]
    return None


def replace_event(scn: Scenario, eid: str, **changes) -> None:
    ev = find_event(scn, eid)
    if ev is None:
        return
    scn.store.remove_event(eid)
    scn.store.add_event(replace(ev, **changes))
