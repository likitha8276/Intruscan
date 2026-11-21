"""Unit tests for report generator and CLI formatting."""

import json
from soc_agent.report_generator import format_markdown_report, generate_containment_playbook


def test_generate_containment_playbook_contains_all_rules():
    record = {
        "incident_id": "TEST-INC-01",
        "src": "192.168.1.100",
        "dst": "10.0.0.5",
        "priority": "HIGH",
        "mitre": [{"technique_id": "T1021.002", "name": "SMB"}],
        "soc_result": {
            "outcome": "PROPOSE",
            "action": {"type": "quarantine_host", "target": "192.168.1.100"},
        },
    }
    pb = generate_containment_playbook(record)
    assert "iptables" in pb
    assert "192.168.1.100" in pb["iptables"]
    assert "ufw" in pb
    assert "192.168.1.100" in pb["ufw"]
    assert "aws_cli" in pb
    assert "cloudflare_waf" in pb
    assert "sigma_rule" in pb
    assert "TEST-INC-01" in pb["sigma_rule"]


def test_format_markdown_report_structure():
    record = {
        "incident_id": "TEST-INC-02",
        "src": "203.0.113.50",
        "dst": "10.0.0.80",
        "kind": "slow_brain",
        "priority": "CRITICAL",
        "disposition": "SLOW_BRAIN_PROPOSE",
        "s_score": 0.885,
        "llm_called": 1,
        "reasons": ["verified_chain_detected"],
        "mitre": [
            {
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactics": "Initial Access",
                "confidence": 0.94,
            }
        ],
        "soc_result": {
            "outcome": "PROPOSE",
            "action": {"type": "block_ip", "target": "203.0.113.50"},
            "verdicts": ["SUPPORTED"],
            "gate_flags": [],
            "llm_ms": 500.0,
            "verify_ms": 0.2,
        },
        "evidence": {
            "logs": {"LOG-01": "Inbound SQL injection payload detected"},
        },
    }

    report = format_markdown_report(record)
    assert "# 🛡️ Incident Investigation Report: TEST-INC-02" in report
    assert "## 1. Executive Summary" in report
    assert "## 2. MITRE ATT&CK® Threat Mapping" in report
    assert "T1190" in report
    assert "## 3. Autonomous Agent Reasoning & Verifier Audit" in report
    assert "SUPPORTED" in report
    assert "## 4. Observed Evidence & Telemetry" in report
    assert "LOG-01" in report
    assert "## 5. Recommended Containment Playbook" in report
    assert "iptables" in report
