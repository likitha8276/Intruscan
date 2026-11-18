"""Layer 1 (Go) <-> parser <-> Layer 2 contract tests. No Go toolchain needed."""
import json
import re
from pathlib import Path

import pytest

from soc_agent.flow_contract import (
    CANONICAL_FIELDS, OPTIONAL_FIELDS, REQUIRED_FIELDS, check_jsonl, flow_problems,
)
from tests.test_parse_cicids2017 import sample
from tools.parse_cicids2017 import convert_row

ROOT = Path(__file__).resolve().parents[1]
GO_SRC = (ROOT / "ingestion" / "main.go").read_text(encoding="utf-8")


def _go_struct_fields() -> dict[str, bool]:
    """json tag -> required?, from the flowRecord struct (pointer or non-omitempty = required)."""
    body = re.search(r"type flowRecord struct \{(.*?)\n\}", GO_SRC, re.S).group(1)
    fields = {}
    for line in body.splitlines():
        m = re.search(r'`json:"([a-z_]+)(,omitempty)?"`', line)
        if m:
            fields[m.group(1)] = m.group(2) is None
    return fields


def test_python_contract_matches_go_struct():
    go = _go_struct_fields()
    assert set(go) == set(CANONICAL_FIELDS)
    assert {k for k, req in go.items() if req} == set(REQUIRED_FIELDS)
    assert {k for k, req in go.items() if not req} == set(OPTIONAL_FIELDS)


def test_go_rejects_unknown_fields_so_flows_must_not_carry_signatures():
    assert "DisallowUnknownFields()" in GO_SRC
    assert "provenance_signature" not in CANONICAL_FIELDS
    flow = json.loads((ROOT / "sample_flows.jsonl").read_text().splitlines()[0])
    assert flow_problems({**flow, "provenance_signature": "x"}) == [
        "unknown field 'provenance_signature'"
    ]


def test_sample_flows_satisfy_contract():
    assert check_jsonl(str(ROOT / "sample_flows.jsonl")) == []


def test_cicids_parser_output_satisfies_contract():
    assert flow_problems(convert_row(sample(), "tuesday", 1)) == []


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda f: f.pop("packets"), "packets is required"),
        (lambda f: f.update(src_port=70000), "src_port must be an integer in 0..65535"),
        (lambda f: f.update(duration_ms=-1), "duration_ms must be a finite non-negative number"),
        (lambda f: f.update(timestamp="2026-11-03 10:00:00"), "timestamp must be RFC3339"),
        (lambda f: f.update(features={"x": -1}), "must be a non-negative number"),
        (lambda f: f.update(protocol=" "), "protocol must be a non-empty string"),
    ],
)
def test_invalid_records_are_reported(mutate, expected):
    flow = json.loads((ROOT / "sample_flows.jsonl").read_text().splitlines()[0])
    mutate(flow)
    assert any(expected in p for p in flow_problems(flow))


def test_scored_fields_only_allowed_when_requested():
    flow = json.loads((ROOT / "sample_flows.jsonl").read_text().splitlines()[0])
    flow.update(s_score=0.5, route="CLEAR")
    assert flow_problems(flow)
    assert flow_problems(flow, allow_scored=True) == []
