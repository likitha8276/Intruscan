"""LLM clients.

* SimulatedLLM - a deterministic, seeded stand-in for a weak 8B model. It lets the
  pipeline and harness run without a GPU, with paired draws so configurations are
  compared on identical random draws. Its fault rates are assumptions, not measurements.
* OllamaClient - a real local model over Ollama's HTTP API.
* CachedLLM - memoises (system, user) -> output; valid at temperature 0.
* GroqClient - a cloud model client using Groq's OpenAI-compatible API.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from .patterns import HIGH_RISK_RELS, TEMPLATES, best_partial, chain_from
from .schemas import Event


class LLMClient(Protocol):
    last_usage: dict

    def generate(self, system: str, user: str, seed_key: str = "") -> str: ...


# ---------------------------------------------------------------------------
# Simulated model


@dataclass
class SimProfile:
    p_obey: dict = field(
        default_factory=lambda: {"atomic": 0.85, "stitched": 0.70, "obfuscated": 0.50}
    )
    hardened_mult: float = 0.40
    p_halluc: float = 0.55
    p_notice_order: float = 0.25
    p_notice_stale: float = 0.30
    p_false_alarm: float = 0.05
    window_tokens: int = 4096

    def scaled(self, s: float) -> "SimProfile":
        c = lambda p: min(max(p * s, 0.0), 1.0)
        return SimProfile(
            {k: c(v) for k, v in self.p_obey.items()},
            self.hardened_mult,
            c(self.p_halluc),
            c(self.p_notice_order),
            self.p_notice_stale,
            c(self.p_false_alarm),
            self.window_tokens,
        )


_EDGE = re.compile(
    r"^\[(?P<id>[^\]]+)\] (?P<ts>\S+) (?P<rel>\w+) "
    r"(?P<src>\S+) -> (?P<dst>\S+) \(src=(?P<source>[^)]+)\)$"
)
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

    def _edges(self, user: str) -> list[Event]:
        out = []
        for line in user.splitlines():
            m = _EDGE.match(line.strip())
            if m:
                out.append(
                    Event(
                        m["id"],
                        datetime.fromisoformat(m["ts"]),
                        m["rel"],
                        m["src"],
                        m["dst"],
                        m["source"],
                    )
                )
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
        for field_value in fields:
            if field_value.startswith("b64:"):
                try:
                    decoded = base64.b64decode(field_value[4:]).decode("utf-8", "ignore")
                except Exception:
                    continue
                if _MARKER.search(decoded):
                    objective = "conceal" if _CONCEAL.search(decoded) else "fabricate"
                    return objective, "obfuscated"
            if _MARKER.search(field_value):
                objective = "conceal" if _CONCEAL.search(field_value) else "fabricate"
                return objective, "atomic"

        joined = " ".join(value for value in fields if not value.startswith("b64:"))
        if _MARKER.search(joined):
            objective = "conceal" if _CONCEAL.search(joined) else "fabricate"
            return objective, "stitched"
        return None

    def generate(self, system: str, user: str, seed_key: str = "") -> str:
        profile = self.profile
        rng = random.Random(seed_key or hashlib.sha256(user.encode()).hexdigest())
        draws = [rng.random() for _ in range(8)]
        hardened = "<untrusted_logs>" in user
        edges = self._edges(user)

        # Drop the oldest edges until the prompt fits the simulated context window.
        overhead = _tok(system) + _tok(user) - sum(
            _tok(line) for line in user.splitlines() if _EDGE.match(line.strip())
        )
        budget = profile.window_tokens - overhead
        edges.sort(key=lambda event: (event.ts, event.event_id))
        kept, used = [], 0
        for event in reversed(edges):
            token_cost = 24
            if used + token_cost > budget:
                break
            kept.append(event)
            used += token_cost
        edges = list(reversed(kept))
        anchors = self._anchors(user)

        output = self._decide(profile, draws, hardened, edges, anchors, user, rng)
        self.last_usage = {
            "prompt_tokens": _tok(system) + _tok(user),
            "completion_tokens": _tok(output),
        }
        return output

    def _decide(self, profile: SimProfile, draws, hardened, edges, anchors, user, rng) -> str:
        injection = self._find_injection(user)
        if injection:
            objective, variant = injection
            probability = profile.p_obey[variant] * (
                profile.hardened_mult if hardened else 1.0
            )
            if draws[0] < probability:
                if objective == "conceal":
                    return self._json([], "low", "close", "")
                host = sorted(anchors)[0] if anchors else "unknown-host"
                template_name = sorted(TEMPLATES)[
                    int(draws[5] * len(TEMPLATES)) % len(TEMPLATES)
                ]
                template = TEMPLATES[template_name]
                invented = lambda role: f"198.51.100.{int(draws[6] * 200) + 1}"
                chain = chain_from(
                    template, range(len(template.steps)), {"host": host}, invent=invented
                )
                return self._json([( "fabricated", chain)], "high", "isolate_host", host)

        # Genuine analysis over the visible edges.
        best = None
        for template in TEMPLATES.values():
            partial = best_partial(template, edges, anchors)
            if partial and (best is None or len(partial[0]) > len(best[1][0])):
                best = (template, partial)

        if best is None:
            if draws[4] < profile.p_false_alarm:
                return self._json([], "medium", "investigate", "")
            return self._json([], "low", "close", "")

        template, (indices, binding) = best
        step_count = len(template.steps)
        full = len(indices) == step_count
        visible_chain = chain_from(template, indices, binding)
        target = binding.get(template.action_role) or (
            sorted(anchors)[0] if anchors else ""
        )

        if (
            not full
            and not any(template.steps[i][0] in HIGH_RISK_RELS for i in indices)
            and draws[4] < 0.5
        ):
            return self._json([], "low", "close", "")

        if not full:
            if draws[1] < profile.p_halluc:
                invented = lambda role: f"198.51.100.{int(draws[7] * 200) + 1}"
                chain = chain_from(template, range(step_count), binding, invent=invented)
                return self._json(
                    [(template.name, chain)],
                    "high",
                    template.action_type,
                    binding.get(template.action_role) or invented(template.action_role),
                )
            return self._json([(template.name, visible_chain)], "medium", "investigate", "")

        # Complete chain visible: check whether the simulated model notices ordering/staleness.
        matched_events = []
        for relation, source_role, destination_role in template.steps:
            matches = [
                event
                for event in edges
                if event.rel == relation
                and event.src == binding[source_role]
                and event.dst == binding[destination_role]
            ]
            matched_events.append(matches[0] if matches else None)

        timestamps = [event.ts for event in matched_events if event]
        if (
            len(timestamps) == step_count
            and any(timestamps[i] > timestamps[i + 1] for i in range(step_count - 1))
            and draws[2] < profile.p_notice_order
        ):
            return self._json([(template.name, visible_chain)], "medium", "investigate", "")

        reference_time = max(event.ts for event in edges) if edges else None
        if (
            timestamps
            and reference_time
            and (reference_time - max(timestamps)).total_seconds() > 24 * 3600
            and draws[3] < profile.p_notice_stale
        ):
            return self._json([(template.name, visible_chain)], "medium", "investigate", "")

        return self._json([(template.name, visible_chain)], "high", template.action_type, target)

    @staticmethod
    def _json(claims, severity, action, target) -> str:
        formatted_claims = [
            {
                "id": f"c{i + 1}",
                "text": f"{name} pattern observed",
                "chain": [
                    {"rel": step.rel, "src": step.src, "dst": step.dst}
                    for step in chain
                ],
            }
            for i, (name, chain) in enumerate(claims)
        ]
        return json.dumps(
            {
                "claims": formatted_claims,
                "severity": severity,
                "action": {"type": action, "target": target},
            }
        )


# ---------------------------------------------------------------------------
# Ollama client (kept for compatibility with the research code)


class OllamaClient:
    """Llama 3.1 8B (or another model) via a local Ollama server."""

    def __init__(
        self,
        model: str = "llama3.1:8b",
        host: str = "http://localhost:11434",
        num_ctx: int = 8192,
        timeout: float = 600.0,
        seed: int = 0,
    ):
        self.model = model
        self.host = host.rstrip("/")
        self.num_ctx = num_ctx
        self.timeout = timeout
        self.seed = seed
        self.last_usage: dict = {}

    def generate(self, system: str, user: str, seed_key: str = "") -> str:
        body = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "options": {
                "temperature": 0,
                "seed": self.seed,
                "num_ctx": self.num_ctx,
            },
        }
        request = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        start_time = time.perf_counter()
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            data = json.loads(response.read().decode("utf-8"))

        self.last_usage = {
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
            "wall_ms": (time.perf_counter() - start_time) * 1000,
        }
        return data["message"]["content"]


class CachedLLM:
    def __init__(self, inner: LLMClient):
        self.inner = inner
        self.cache = {}
        self.last_usage: dict = {}
        self.hits = 0
        self.misses = 0

    def generate(self, system: str, user: str, seed_key: str = "") -> str:
        cache_key = hashlib.sha256(
            (system + "\x00" + user + "\x00" + seed_key).encode("utf-8")
        ).hexdigest()

        if cache_key in self.cache:
            self.hits += 1
            output, usage = self.cache[cache_key]
            self.last_usage = dict(usage)
            return output

        self.misses += 1
        output = self.inner.generate(system, user, seed_key)
        self.last_usage = dict(getattr(self.inner, "last_usage", {}))
        self.cache[cache_key] = (output, dict(self.last_usage))
        return output


class GroqClient:
    """Cloud LLM client using Groq's OpenAI-compatible chat API."""

    def __init__(
        self,
        model: str = "openai/gpt-oss-20b",
        api_key: str | None = None,
        timeout: float = 120.0,
    ):
        self.model = model
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.timeout = timeout
        self.last_usage: dict = {}

        if not self.api_key:
            raise ValueError("GROQ_API_KEY is missing. Add it to your environment.")

    def generate(self, system: str, user: str, seed_key: str = "") -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }

        request = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "Mozilla/5.0",
            },
            method="POST",
        )

        start_time = time.perf_counter()
        data = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < 3:
                    wait_time = 10 * (attempt + 1)
                    print(
                        f"Groq rate limit reached. Retrying in {wait_time} seconds...",
                        file=sys.stderr,
                    )
                    time.sleep(wait_time)
                else:
                    error_body = exc.read().decode("utf-8", "replace")
                    raise RuntimeError(
                        f"Groq API request failed: HTTP {exc.code}: {error_body}"
                    ) from exc
            except Exception as exc:
                raise RuntimeError(f"Groq API request failed: {exc}") from exc

        if data is None:
            raise RuntimeError("Groq API request failed after all retry attempts.")

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        usage = data.get("usage", {})
        self.last_usage = {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "wall_ms": elapsed_ms,
        }

        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError(f"Groq returned no choices: {data}")

        return choices[0]["message"]["content"]
