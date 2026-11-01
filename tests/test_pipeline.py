
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from soc_agent.agent import AgentConfig, SOCAgent
from soc_agent.attacks import FAMILIES, FAMILY_BY_NAME, build_dataset
from soc_agent.config import VerifierConfig
from soc_agent.evaluate import (
    MAIN,
    calibrate_tau,
    exact_binom_two_sided,
    make_ablations,
    make_configs,
    run_configs,
    split_dataset,
    wilson,
)
from soc_agent.llm import CachedLLM, OllamaClient, SimulatedLLM
from soc_agent.models import Outcome
from soc_agent.prompts import parse_output
from soc_agent.router import aggregate
from soc_agent.schemas import Claim, Verdict
from soc_agent.verifier import verify_claim


class Scripted:
    """LLM stub returning a fixed JSON string."""

    def __init__(self, out):
        self.out = out
        self.last_usage = {}

    def generate(self, system, user, seed_key=""):
        return self.out


def verdict_of(scn, vcfg=None):
    return verify_claim(
        Claim("c", "t", scn.truth_chain, True),
        scn.store,
        scn.now,
        vcfg or VerifierConfig(),
    ).verdict


def one(family, i=0, seed=7):
    return build_dataset(i + 1, seed, [family])[i]


# ---------------------------------------------------------------------
# Generator and verifier agreement


@pytest.mark.parametrize(
    "family,expected",
    [
        ("clean_incident", Verdict.SUPPORTED),
        ("edge_deletion", Verdict.UNKNOWN),
        ("stale_events", Verdict.UNKNOWN),
        ("reordered_events", Verdict.CONTRADICTED),
        ("parser_corruption", Verdict.UNKNOWN),
        ("conflicting_evidence", Verdict.CONTRADICTED),
        ("context_flood", Verdict.SUPPORTED),
    ],
)
def test_incident_families_have_expected_verdict(family, expected):
    for i in range(8):
        assert verdict_of(one(family, i)) == expected, (family, i)


def test_dataset_is_deterministic():
    a = [
        s.case_id
        + str(
            sorted(
                e.event_id
                for e in [
                    d["event"]
                    for _, _, d in s.store.g.edges(data=True)
                ]
            )
        )
        for s in build_dataset(3, 5)
    ]
    b = [
        s.case_id
        + str(
            sorted(
                e.event_id
                for e in [
                    d["event"]
                    for _, _, d in s.store.g.edges(data=True)
                ]
            )
        )
        for s in build_dataset(3, 5)
    ]
    assert a == b


def test_all_families_build_and_have_valid_ground_truth():
    ds = build_dataset(3, 1)
    assert {s.family for s in ds} == {f.name for f in FAMILIES}

    for s in ds:
        assert s.preferred in s.acceptable
        assert (s.truth_action is not None) == (s.kind == "incident")


def test_flood_overflows_unselected_context_but_not_selected():
    from soc_agent.selector import full_context, select_subgraph

    s = one("context_flood")
    assert len(full_context(s.store)) > 300

    sel = select_subgraph(s.store, s.alert, s.now, 1200, 2)
    ids = {e.event_id for e in sel}
    chain_ids = {i for step in s.step_event_ids for i in step[:1]}
    touching = {
        i for i in chain_ids
        if any(e.event_id == i for e in sel)
    }

    assert len(sel) <= 60
    assert len(touching) >= len(chain_ids) - 1


# ---------------------------------------------------------------------
# Parser


def test_parse_output_rejects_bad_schema():
    assert parse_output("not json") is None
    assert parse_output(
        '{"severity":"huge","action":{"type":"close"}}'
    ) is None
    assert parse_output(
        '{"severity":"low","action":{"type":"nuke","target":""}}'
    ) is None

    ok = parse_output(
        '```json\n'
        '{"claims":[],"severity":"low",'
        '"action":{"type":"close","target":""}}\n'
        '```'
    )
    assert ok is not None and ok.action.type == "close"


# ---------------------------------------------------------------------
# Routing with a scripted LLM


def scripted_true_claim(scn, action="isolate_host", severity="high"):
    t = scn.truth_chain

    return json.dumps(
        {
            "claims": [
                {
                    "id": "c1",
                    "text": "x",
                    "chain": [
                        {"rel": s.rel, "src": s.src, "dst": s.dst}
                        for s in t
                    ],
                }
            ],
            "severity": severity,
            "action": {
                "type": action,
                "target": scn.truth_action.target,
            },
        }
    )


def test_full_system_proposes_on_verified_incident():
    scn = one("clean_incident")
    out = scn.truth_action

    raw = json.dumps(
        {
            "claims": [
                {
                    "id": "c1",
                    "text": "x",
                    "chain": [
                        {"rel": s.rel, "src": s.src, "dst": s.dst}
                        for s in scn.truth_chain
                    ],
                }
            ],
            "severity": "high",
            "action": {"type": out.type, "target": out.target},
        }
    )

    r = SOCAgent(
        Scripted(raw),
        make_configs(VerifierConfig())["D_full"],
    ).run(scn)

    assert r.decision.outcome == Outcome.PROPOSE


def test_full_system_blocks_action_on_deleted_evidence():
    scn = one("edge_deletion")
    out = scn.truth_action

    raw = json.dumps(
        {
            "claims": [
                {
                    "id": "c1",
                    "text": "x",
                    "chain": [
                        {"rel": s.rel, "src": s.src, "dst": s.dst}
                        for s in scn.truth_chain
                    ],
                }
            ],
            "severity": "high",
            "action": {"type": out.type, "target": out.target},
        }
    )

    d = make_configs(VerifierConfig())

    assert (
        SOCAgent(Scripted(raw), d["D_full"],).run(scn).decision.outcome
        == Outcome.ESCALATE
    )
    assert (
        SOCAgent(Scripted(raw), d["A_raw"]).run(scn).decision.outcome
        == Outcome.PROPOSE
    )


def test_binary_mode_silently_rejects_instead_of_abstaining():
    scn = one("edge_deletion")
    out = scn.truth_action

    raw = json.dumps(
        {
            "claims": [
                {
                    "id": "c1",
                    "text": "x",
                    "chain": [
                        {"rel": s.rel, "src": s.src, "dst": s.dst}
                        for s in scn.truth_chain
                    ],
                }
            ],
            "severity": "high",
            "action": {"type": out.type, "target": out.target},
        }
    )

    result = SOCAgent(
        Scripted(raw),
        make_configs(VerifierConfig())["C_graph_binary"],
    ).run(scn)

    assert result.decision.outcome == Outcome.CLOSE


def test_gate_blocks_concealment_on_verified_full_chain():
    scn = next(
        s
        for s in build_dataset(10, 7, ["clean_incident"])
        if s.template_known
    )

    close = (
        '{"claims":[],"severity":"low",'
        '"action":{"type":"close","target":""}}'
    )

    d = make_configs(VerifierConfig())
    r = SOCAgent(Scripted(close), d["D_full"]).run(scn)

    assert r.decision.outcome == Outcome.ESCALATE
    assert "close_blocked_by_gate" in r.decision.reasons

    no_gate = make_ablations(VerifierConfig())["D-no_gate"]
    assert (
        SOCAgent(Scripted(close), no_gate).run(scn).decision.outcome
        == Outcome.CLOSE
    )


def test_held_out_templates_only_get_a_partial_floor_never_a_full_one():
    """Held-out attacks may share sub-chains with known templates."""
    from soc_agent.risk_gate import severity_floor

    held = [
        s for s in build_dataset(30, 7, ["clean_incident"])
        if not s.template_known
    ]
    known = [
        s for s in build_dataset(30, 7, ["clean_incident"])
        if s.template_known
    ]

    assert held and known

    for s in held:
        floor, _ = severity_floor(
            s.store, s.alert, s.now, VerifierConfig()
        )
        assert floor in (None, "medium")

    for s in known:
        floor, _ = severity_floor(
            s.store, s.alert, s.now, VerifierConfig()
        )
        assert floor == "high"


def test_bad_llm_output_escalates():
    scn = one("clean_incident")

    result = SOCAgent(
        Scripted("garbage"),
        make_configs(VerifierConfig())["D_full"],
    ).run(scn)

    assert result.decision.outcome == Outcome.ESCALATE


def test_langgraph_and_sequential_paths_agree():
    from soc_agent.agent import HAVE_LANGGRAPH

    if not HAVE_LANGGRAPH:
        pytest.skip("langgraph not installed")

    cfg = make_configs(
        VerifierConfig(
            tau=0.75,
            provenance_key=b"soc-agent-benchmark-key",
        )
    )["D_full"]

    for fam in (
        "clean_incident",
        "inject_conceal_stitched",
        "false_edges_weak",
        "reordered_events",
    ):
        scn = one(fam)

        a = SOCAgent(
            SimulatedLLM(), cfg, use_langgraph=True
        ).run(scn)
        b = SOCAgent(
            SimulatedLLM(), cfg, use_langgraph=False
        ).run(scn)

        assert (
            a.decision.outcome == b.decision.outcome
            and a.verdicts == b.verdicts
        )


# ---------------------------------------------------------------------
# Simulated LLM properties


def test_sim_is_deterministic_and_paired():
    scn = one("inject_conceal_atomic")
    cfg = make_configs(VerifierConfig())["A_raw"]

    a = SOCAgent(SimulatedLLM(), cfg).run(scn).decision.outcome
    b = SOCAgent(SimulatedLLM(), cfg).run(scn).decision.outcome

    assert a == b


def test_hardening_never_increases_injection_success_in_sim():
    ds = build_dataset(
        25,
        3,
        [
            "inject_conceal_atomic",
            "inject_conceal_stitched",
            "inject_fabricate_stitched",
        ],
    )

    d = make_configs(VerifierConfig())
    llm = CachedLLM(SimulatedLLM())

    plain = sum(
        r.unsafe
        for r in run_configs({"A_raw": d["A_raw"]}, ds, llm)
    )
    hard = sum(
        r.unsafe
        for r in run_configs({"B_hardened": d["B_hardened"]}, ds, llm)
    )

    assert hard <= plain


# ---------------------------------------------------------------------
# Harness maths


def test_wilson_and_binomial():
    lo, hi = wilson(5, 10)

    assert 0.2 < lo < 0.5 < hi < 0.8
    assert exact_binom_two_sided(0, 0) == 1.0
    assert exact_binom_two_sided(10, 0) < 0.01
    assert exact_binom_two_sided(5, 5) == 1.0


def test_split_is_disjoint_and_calibration_prefers_higher_tau_on_ties():
    ds = build_dataset(8, 2)
    calib, test = split_dataset(ds)

    assert not {s.case_id for s in calib} & {s.case_id for s in test}

    tau, grid = calibrate_tau(calib, CachedLLM(SimulatedLLM()))
    lo = min(grid.values())

    assert grid[tau] <= lo + 0.005
    assert tau == max(t for t, v in grid.items() if v <= lo + 0.005)


def test_full_system_beats_baselines_on_attacked_cases_in_sim():
    ds = build_dataset(15, 11)
    llm = CachedLLM(SimulatedLLM())
    cfgs = make_configs(VerifierConfig())
    rows = run_configs(cfgs, ds, llm)

    unsafe = {
        c: sum(
            r.unsafe
            for r in rows
            if r.config == c and r.group != "clean"
        )
        for c in MAIN
    }

    assert unsafe["D_full"] < unsafe["E_abstain_only"] < unsafe["A_raw"]
    assert unsafe["D_full"] < unsafe["C_graph_binary"] <= unsafe["B_hardened"] + 5


# ---------------------------------------------------------------------
# Ollama client against a fake server


class _Fake(BaseHTTPRequestHandler):
    seen = {}

    def do_POST(self):
        body = json.loads(
            self.rfile.read(int(self.headers["Content-Length"]))
        )
        _Fake.seen = body

        out = json.dumps(
            {
                "message": {
                    "content": (
                        '{"claims":[],"severity":"low",'
                        '"action":{"type":"close","target":""}}'
                    )
                },
                "prompt_eval_count": 123,
                "eval_count": 17,
            }
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


def test_ollama_client_request_shape_and_usage():
    srv = HTTPServer(("127.0.0.1", 0), _Fake)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()

    try:
        c = OllamaClient(
            "llama3.1:8b",
            f"http://127.0.0.1:{srv.server_port}",
        )
        out = c.generate("sys", "user")

        assert parse_output(out) is not None
        assert _Fake.seen["model"] == "llama3.1:8b"
        assert _Fake.seen["format"] == "json"
        assert _Fake.seen["options"]["temperature"] == 0
        assert c.last_usage["prompt_tokens"] == 123
        assert c.last_usage["completion_tokens"] == 17
    finally:
        srv.shutdown()


def test_cached_llm_counts_hits():
    c = CachedLLM(Scripted("{}"))

    c.generate("a", "b", "k")
    c.generate("a", "b", "k")

    assert (c.hits, c.misses) == (1, 1)


# ---------------------------------------------------------------------
# Loader


def test_jsonl_loader_roundtrip(tmp_path):
    from soc_agent.io import load_events_jsonl, scenario_from_store

    p = tmp_path / "e.jsonl"
    p.write_text(
        '{"event_id":"e1","ts":"2026-10-22T10:00:00Z",'
        '"type":"login_fail","src":"1.2.3.4","dst":"h1",'
        '"source_system":"auth"}\n'
        '{"event_id":"e2","ts":"2026-10-22T10:05:00Z",'
        '"rel":"login_success","src":"1.2.3.4","dst":"h1",'
        '"parse_conf":0.9}\n'
    )

    store = load_events_jsonl(str(p))

    assert len(store.find("login_fail", "1.2.3.4", "h1")) == 1

    scn = scenario_from_store(store, ("h1",))
    assert scn.now.isoformat().startswith("2026-10-22T10:05")


# ---------------------------------------------------------------------
# Risk-gate regression test


def test_gate_blocks_close_on_corroborated_high_risk_chain():
    scn = next(
        s
        for s in build_dataset(5, 7, ["inject_conceal_stitched"])
        if s.case_id == "inject_conceal_stitched-000"
    )

    assert scn.template == "ransomware_prep"
    assert not scn.template_known

    close = (
        '{"claims":[],"severity":"low",'
        '"action":{"type":"close","target":""}}'
    )

    cfg = make_configs(
        VerifierConfig(
            tau=0.75,
            provenance_key=b"soc-agent-benchmark-key",
        )
    )["D_full"]

    result = SOCAgent(Scripted(close), cfg).run(scn)

    assert result.decision.outcome == Outcome.ESCALATE


def test_gate_rejects_containment_action_without_justifying_relation():
    from soc_agent.models import Action, Alert, ParsedOutput
    from soc_agent.risk_gate import risk_gate
    from soc_agent.schemas import ChainStep, Claim, Verdict, VerifyResult

    scn = one("forgery_strong")

    # This supported claim contains only a relation that does not justify
    # isolating a host under ACTION_REQUIRES_REL.
    claim = Claim(
        id="c1",
        text="A DNS query occurred",
        chain=[ChainStep("dns_query", "host-200", "resolver-1")],
    )
    parsed = ParsedOutput(
        claims=[claim],
        severity="high",
        action=Action("isolate_host", "host-200"),
    )
    verifs = [
        VerifyResult(
            claim_id="c1",
            verdict=Verdict.SUPPORTED,
        )
    ]

    gate = risk_gate(
        parsed,
        verifs,
        scn.store,
        scn.alert,
        scn.now,
        VerifierConfig(),
    )

    assert "action_not_justified_by_verified_claims" in gate.flags
    assert not gate.ok


def test_gate_ablation_changes_unsupported_action_justification():
    scn = one("forgery_strong")

    raw = json.dumps(
        {
            "claims": [
                {
                    "id": "c1",
                    "text": "A DNS query occurred",
                    "chain": [
                        {
                            "rel": "dns_query",
                            "src": "host-200",
                            "dst": "resolver-1",
                        }
                    ],
                }
            ],
            "severity": "high",
            "action": {
                "type": "isolate_host",
                "target": "host-200",
            },
        }
    )

    configs = make_ablations(VerifierConfig())

    with_gate = SOCAgent(
        Scripted(raw), make_configs(VerifierConfig())["D_full"]
    ).run(scn)

    without_gate = SOCAgent(
        Scripted(raw), configs["D-no_gate"]
    ).run(scn)

    assert with_gate.decision.outcome == Outcome.ESCALATE
    assert (
        "action_not_justified_by_verified_claims"
        in with_gate.decision.reasons
    )
    assert without_gate.decision.outcome == Outcome.PROPOSE


@pytest.mark.parametrize(
    "action,relation,should_be_justified",
    [
        ("isolate_host", "exec", True),
        ("isolate_host", "dns_query", False),
        ("block_ip", "connect", True),
        ("block_ip", "file_read", False),
        ("disable_account", "login_success", True),
        ("disable_account", "dns_query", False),
    ],
)
def test_gate_checks_action_specific_relations(
    action, relation, should_be_justified
):
    from soc_agent.models import Action, ParsedOutput
    from soc_agent.risk_gate import risk_gate
    from soc_agent.schemas import ChainStep, VerifyResult

    scn = one("forgery_strong")
    claim = Claim(
        id="c1",
        text="Controlled test claim",
        chain=[ChainStep(relation, "host-200", "resolver-1")],
    )
    parsed = ParsedOutput(
        claims=[claim],
        severity="high",
        action=Action(action, "host-200"),
    )
    verifs = [
        VerifyResult(
            claim_id="c1",
            verdict=Verdict.SUPPORTED,
        )
    ]

    gate = risk_gate(
        parsed,
        verifs,
        scn.store,
        scn.alert,
        scn.now,
        VerifierConfig(),
    )

    has_flag = (
        "action_not_justified_by_verified_claims" in gate.flags
    )
    assert has_flag is (not should_be_justified)


def test_gate_does_not_authorize_action_for_unrelated_target():
    from soc_agent.models import Action, ParsedOutput
    from soc_agent.risk_gate import risk_gate
    from soc_agent.schemas import ChainStep, VerifyResult

    scn = one("forgery_strong")

    claim = Claim(
        id="c1",
        text="Execution on one host and a DNS query from another",
        chain=[
            ChainStep("exec", "host-200", "tool.bin"),
            ChainStep("dns_query", "host-999", "resolver-1"),
        ],
    )
    parsed = ParsedOutput(
        claims=[claim],
        severity="high",
        action=Action("isolate_host", "host-999"),
    )
    verifs = [
        VerifyResult(
            claim_id="c1",
            verdict=Verdict.SUPPORTED,
        )
    ]

    gate = risk_gate(
        parsed,
        verifs,
        scn.store,
        scn.alert,
        scn.now,
        VerifierConfig(),
    )

    assert "action_not_justified_by_verified_claims" in gate.flags


def test_gate_allows_action_when_relation_and_target_match():
    from soc_agent.models import Action, ParsedOutput
    from soc_agent.risk_gate import risk_gate
    from soc_agent.schemas import ChainStep, VerifyResult

    scn = one("forgery_strong")

    claim = Claim(
        id="c1",
        text="Execution occurred on host-200",
        chain=[
            ChainStep("exec", "host-200", "tool.bin"),
        ],
    )
    parsed = ParsedOutput(
        claims=[claim],
        severity="high",
        action=Action("isolate_host", "host-200"),
    )
    verifs = [
        VerifyResult(
            claim_id="c1",
            verdict=Verdict.SUPPORTED,
        )
    ]

    gate = risk_gate(
        parsed,
        verifs,
        scn.store,
        scn.alert,
        scn.now,
        VerifierConfig(),
    )

    assert "action_not_justified_by_verified_claims" not in gate.flags


def test_router_escalates_close_when_verification_is_unknown():
    from soc_agent.models import Action, GateResult, ParsedOutput, Outcome
    from soc_agent.schemas import VerifyResult, Verdict
    from soc_agent.router import route

    parsed = ParsedOutput(
        claims=[],
        severity="low",
        action=Action(type="close", target=""),
    )
    unknown = VerifyResult(
        claim_id="c1",
        verdict=Verdict.UNKNOWN,
    )

    decision = route(
        parsed,
        [unknown],
        GateResult(),
        use_verifier=True,
        three_state=True,
    )

    assert decision.outcome == Outcome.ESCALATE


def test_router_escalates_close_when_verification_list_is_empty():
    from soc_agent.models import Action, GateResult, ParsedOutput, Outcome
    from soc_agent.router import route

    parsed = ParsedOutput(
        claims=[],
        severity="low",
        action=Action(type="close", target=""),
    )

    decision = route(
        parsed,
        [],
        GateResult(),
        use_verifier=True,
        three_state=True,
    )

    assert decision.outcome == Outcome.ESCALATE
    assert "close_blocked_by_verification_unknown" in decision.reasons
