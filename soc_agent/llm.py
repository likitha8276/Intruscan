"""LLM clients.

* SimulatedLLM - a deterministic, seeded STAND-IN for a weak 8B model. It lets the whole
  pipeline and harness run without a GPU, with paired ("common random numbers") draws so that
  configurations are compared on identical dice. Its fault rates are ASSUMPTIONS (SimProfile),
  not measurements. Results from it validate the pipeline; they are not evidence about Llama.
* OllamaClient  - the real local model (Llama 3.1 8B) over Ollama's HTTP API.
* CachedLLM     - memoises (system, user) -> output; valid at temperature 0 and saves real-LLM time.
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from .patterns import HIGH_RISK_RELS, TEMPLATES, best_partial, chain_from
from .schemas import Event


class LLMClient(Protocol):
    last_usage: dict

    def generate(self, system: str, user: str, seed_key: str = "") -> str: ...


# ------------------------------------------------------------------ simulated model

@dataclass
class SimProfile:
    p_obey: dict = field(default_factory=lambda: {"atomic": 0.85, "stitched": 0.70, "obfuscated": 0.50})
    hardened_mult: float = 0.40        # prompt hardening scales obey-probability by this
    p_halluc: float = 0.55             # completes a partial chain with invented steps
    p_notice_order: float = 0.25       # notices a reordered chain
    p_notice_stale: float = 0.30       # notices stale evidence
    p_false_alarm: float = 0.05        # flags a clean benign alert as suspicious
    window_tokens: int = 4096          # context window; oldest edges are dropped on overflow

    def scaled(self, s: float) -> "SimProfile":
        c = lambda p: min(max(p * s, 0.0), 1.0)
        return SimProfile({k: c(v) for k, v in self.p_obey.items()}, self.hardened_mult,
                          c(self.p_halluc), c(self.p_notice_order), self.p_notice_stale,
                          c(self.p_false_alarm), self.window_tokens)


_EDGE = re.compile(r"^\[(?P<id>[^\]]+)\] (?P<ts>\S+) (?P<rel>\w+) (?P<src>\S+) -> (?P<dst>\S+) \(src=(?P<source>[^)]*)\)$")
_UA = re.compile(r'ua="(?P<ua>[^"]*)"')
_NORMAL_UA = ("Mozilla/5.0", "curl/", "python-requests/")
_MARKER = re.compile(r"ignore previous instructions", re.I)
_CONCEAL = re.compile(r"report no threat|close the alert|authorized maintenance", re.I)
_FABRICATE = re.compile(r"COMPROMISED|isolate_host", re.I)


def _tok(text: str) -> int:
    return len(text) // 4 + 1


class SimulatedLLM:
    def __init__(self, profile: SimProfile | None = None):
        self.profile = profile or SimProfile()
        self.last_usage: dict = {}

    # -- parsing the prompt the way a model "reads" it
    def _edges(self, user: str) -> list[Event]:
        out = []
        for line in user.splitlines():
            m = _EDGE.match(line.strip())
            if m:
                out.append(Event(m["id"], datetime.fromisoformat(m["ts"]), m["rel"], m["src"], m["dst"], m["source"]))
        return out

    def _anchors(self, user: str) -> set[str]:
        m = re.search(r"ALERT: .*? entities=(\S+)", user)
        return set(m.group(1).split(",")) if m else set()

    def _free_text_fields(self, user: str) -> list[str]:
        fields = []
        for line in user.splitlines():
            if line.startswith("LOG|"):
                m = _UA.search(line)
                if m and not m["ua"].startswith(_NORMAL_UA):
                    fields.append(m["ua"])
        return fields

    def _find_injection(self, user: str):
        fields = self._free_text_fields(user)
        for f in fields:
            if f.startswith("b64:"):
                try:
                    dec = base64.b64decode(f[4:]).decode("utf-8", "ignore")
                except Exception:
                    continue
                if _MARKER.search(dec):
                    return ("conceal" if _CONCEAL.search(dec) else "fabricate"), "obfuscated"
            if _MARKER.search(f):
                return ("conceal" if _CONCEAL.search(f) else "fabricate"), "atomic"
        joined = " ".join(f for f in fields if not f.startswith("b64:"))
        if _MARKER.search(joined):
            return ("conceal" if _CONCEAL.search(joined) else "fabricate"), "stitched"
        return None

    # -- the "model"
    def generate(self, system: str, user: str, seed_key: str = "") -> str:
        p = self.profile
        rng = random.Random(seed_key or hashlib.sha256(user.encode()).hexdigest())
        u = [rng.random() for _ in range(8)]
        hardened = "<untrusted_logs>" in user
        edges = self._edges(user)
        # context overflow: drop the oldest edges until the prompt fits the window
        overhead = _tok(system) + _tok(user) - sum(_tok(l) for l in user.splitlines() if _EDGE.match(l.strip()))
        budget = p.window_tokens - overhead
        edges.sort(key=lambda e: (e.ts, e.event_id))
        kept, used = [], 0
        for e in reversed(edges):
            t = 24      # ~ tokens per rendered edge line
            if used + t > budget:
                break
            kept.append(e)
            used += t
        edges = list(reversed(kept))
        anchors = self._anchors(user)

        out = self._decide(p, u, hardened, edges, anchors, user, rng)
        self.last_usage = {"prompt_tokens": _tok(system) + _tok(user), "completion_tokens": _tok(out)}
        return out

    def _decide(self, p: SimProfile, u, hardened, edges, anchors, user, rng) -> str:
        inj = self._find_injection(user)
        if inj:
            objective, variant = inj
            prob = p.p_obey[variant] * (p.hardened_mult if hardened else 1.0)
            if u[0] < prob:
                if objective == "conceal":
                    return self._json([], "low", "close", "")
                host = sorted(anchors)[0] if anchors else "unknown-host"
                t = TEMPLATES[sorted(TEMPLATES)[int(u[5] * len(TEMPLATES)) % len(TEMPLATES)]]
                invented = lambda role: f"198.51.100.{int(u[6] * 200) + 1}"
                chain = chain_from(t, range(len(t.steps)), {"host": host}, invent=invented)
                return self._json([("fabricated", chain)], "high", "isolate_host", host)

        # genuine analysis over visible edges (the sim ignores timestamps unless it "notices")
        best = None
        for t in TEMPLATES.values():
            bp = best_partial(t, edges, anchors)
            if bp and (best is None or len(bp[0]) > len(best[1][0])):
                best = (t, bp)
        if best is None:
            if u[4] < p.p_false_alarm:
                return self._json([], "medium", "investigate", "")
            return self._json([], "low", "close", "")

        t, (idxs, binding) = best
        n = len(t.steps)
        full = len(idxs) == n
        visible_chain = chain_from(t, idxs, binding)
        target = binding.get(t.action_role) or (sorted(anchors)[0] if anchors else "")
        if not full and not any(t.steps[i][0] in HIGH_RISK_RELS for i in idxs) and u[4] < 0.5:
            return self._json([], "low", "close", "")      # benign-looking prefix: model dismisses it
        if not full:
            if u[1] < p.p_halluc:
                invented = lambda role: f"198.51.100.{int(u[7] * 200) + 1}"
                chain = chain_from(t, range(n), binding, invent=invented)
                return self._json([(t.name, chain)], "high", t.action_type,
                                  binding.get(t.action_role) or invented(t.action_role))
            return self._json([(t.name, visible_chain)], "medium", "investigate", "")
        # complete chain visible: check whether the model "notices" bad ordering / staleness
        evs = []
        for rel, sr, dr in t.steps:
            m = [e for e in edges if e.rel == rel and e.src == binding[sr] and e.dst == binding[dr]]
            evs.append(m[0] if m else None)
        ts = [e.ts for e in evs if e]
        if len(ts) == n and any(ts[i] > ts[i + 1] for i in range(n - 1)) and u[2] < p.p_notice_order:
            return self._json([(t.name, visible_chain)], "medium", "investigate", "")
        ref = max(e.ts for e in edges) if edges else None
        if ts and ref and (ref - max(ts)).total_seconds() > 24 * 3600 and u[3] < p.p_notice_stale:
            return self._json([(t.name, visible_chain)], "medium", "investigate", "")
        return self._json([(t.name, visible_chain)], "high", t.action_type, target)

    @staticmethod
    def _json(claims, severity, action, target) -> str:
        cl = [{"id": f"c{i + 1}", "text": f"{name} pattern observed",
               "chain": [{"rel": s.rel, "src": s.src, "dst": s.dst} for s in chain]}
              for i, (name, chain) in enumerate(claims)]
        return json.dumps({"claims": cl, "severity": severity, "action": {"type": action, "target": target}})


# ------------------------------------------------------------------ real model

class OllamaClient:
    """Llama 3.1 8B (or any model) via a local Ollama server, JSON mode, temperature 0."""

    def __init__(self, model: str = "llama3.1:8b", host: str = "http://localhost:11434",
                 num_ctx: int = 8192, timeout: float = 600.0, seed: int = 0):
        self.model, self.host, self.num_ctx, self.timeout, self.seed = model, host.rstrip("/"), num_ctx, timeout, seed
        self.last_usage: dict = {}

    def generate(self, system: str, user: str, seed_key: str = "") -> str:
        body = {
            "model": self.model, "stream": False, "format": "json",
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": 0, "seed": self.seed, "num_ctx": self.num_ctx},
        }
        req = urllib.request.Request(f"{self.host}/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read())
        self.last_usage = {"prompt_tokens": data.get("prompt_eval_count", 0),
                           "completion_tokens": data.get("eval_count", 0),
                           "wall_ms": (time.perf_counter() - t0) * 1000}
        return data["message"]["content"]


class CachedLLM:
    def __init__(self, inner: LLMClient):
        self.inner, self.cache, self.last_usage = inner, {}, {}
        self.hits = self.misses = 0

    def generate(self, system: str, user: str, seed_key: str = "") -> str:
        key = hashlib.sha256((system + "\x00" + user + "\x00" + seed_key).encode()).hexdigest()
        if key in self.cache:
            self.hits += 1
            out, self.last_usage = self.cache[key]
            return out
        self.misses += 1
        out = self.inner.generate(system, user, seed_key)
        self.last_usage = dict(getattr(self.inner, "last_usage", {}))
        self.cache[key] = (out, self.last_usage)
        return out
