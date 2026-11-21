"""Security Operations Center (SOC) incident report and playbook generator.

Generates executive-ready markdown reports, SIEM detection rules (Sigma),
and infrastructure containment scripts from verified incident records.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any


def generate_containment_playbook(record: dict[str, Any]) -> dict[str, str]:
    """Generate multi-platform remediation commands and SIEM detection rules."""
    src = str(record.get("src") or "unknown_host")
    dst = str(record.get("dst") or "internal_network")
    incident_id = str(record.get("incident_id") or "INC-UNKNOWN")
    action_type = "contain"
    soc = record.get("soc_result") or {}
    if isinstance(soc, dict) and soc.get("action"):
        act = soc["action"]
        if isinstance(act, dict):
            action_type = act.get("type", "quarantine_host")
            src = act.get("target", src)

    # Linux iptables
    iptables_cmd = (
        f"# Immediate Host / IP Containment for {incident_id}\n"
        f"sudo iptables -I INPUT 1 -s {src} -j DROP -m comment --comment \"SOC-GATE-BLOCK-{incident_id}\"\n"
        f"sudo iptables -I FORWARD 1 -s {src} -j DROP -m comment --comment \"SOC-GATE-BLOCK-{incident_id}\"\n"
        f"sudo iptables -I OUTPUT 1 -d {src} -j DROP -m comment --comment \"SOC-GATE-BLOCK-{incident_id}\""
    )

    # Ubuntu UFW
    ufw_cmd = (
        f"# UFW Perimeter Block for {incident_id}\n"
        f"sudo ufw insert 1 deny from {src} comment \"INTRUSCAN SOC Block {incident_id}\""
    )

    # AWS VPC NACL CLI
    aws_cmd = (
        f"# AWS VPC Network ACL Drop Rule\n"
        f"aws ec2 create-network-acl-entry \\\n"
        f"  --network-acl-id acl-0123456789abcdef0 \\\n"
        f"  --ingress \\\n"
        f"  --rule-number 50 \\\n"
        f"  --protocol -1 \\\n"
        f"  --cidr-block {src if '/' in src else src + '/32'} \\\n"
        f"  --rule-action deny"
    )

    # Cloudflare WAF Expression
    cf_waf = json.dumps(
        {
            "description": f"INTRUSCAN SOC Containment - {incident_id}",
            "action": "block",
            "expression": f'(ip.src eq {src}) or (http.request.uri contains "{src}")',
            "enabled": True,
        },
        indent=2,
    )

    # Sigma SIEM Rule
    technique_tags = []
    for m in record.get("mitre") or []:
        tid = m.get("technique_id")
        if tid:
            technique_tags.append(f"  - attack.{tid.lower().replace('.', '_')}")
    if not technique_tags:
        technique_tags = ["  - attack.lateral_movement", "  - attack.t1021_002"]

    sigma_yaml = (
        f"title: INTRUSCAN Automated Detection ({incident_id}) - Suspicious Traffic from {src}\n"
        f"id: {incident_id.lower()}-det-01\n"
        f"status: experimental\n"
        f"description: Detected anomalies and potential adversary activity originating from {src} to {dst}.\n"
        f"references:\n"
        f"  - https://github.com/intruscan/soc-agent-research\n"
        f"author: INTRUSCAN Autonomous SOC Agent\n"
        f"date: {datetime.now().strftime('%Y/%m/%d')}\n"
        f"tags:\n" + "\n".join(technique_tags) + "\n"
        f"logsource:\n"
        f"  category: network_traffic\n"
        f"detection:\n"
        f"  selection:\n"
        f"    SourceIp: '{src}'\n"
        f"    DestinationIp: '{dst}'\n"
        f"  condition: selection\n"
        f"falsepositives:\n"
        f"  - Legitimate administrative maintenance\n"
        f"level: {'critical' if record.get('priority') == 'CRITICAL' else 'high'}\n"
    )

    return {
        "iptables": iptables_cmd,
        "ufw": ufw_cmd,
        "aws_cli": aws_cmd,
        "cloudflare_waf": cf_waf,
        "sigma_rule": sigma_yaml,
    }


def format_markdown_report(record: dict[str, Any]) -> str:
    """Format an incident into a comprehensive CISO/Analyst-grade Markdown report."""
    incident_id = record.get("incident_id", "N/A")
    recorded_at = record.get("recorded_at", datetime.now().isoformat())
    kind = str(record.get("kind", "N/A")).upper()
    priority = str(record.get("priority", "N/A")).upper()
    disposition = record.get("disposition", "N/A")
    src = record.get("src", "N/A")
    dst = record.get("dst", "N/A")
    route = record.get("route", "N/A")
    s_score = record.get("s_score", "N/A")
    score_str = f"{s_score:.4f}" if isinstance(s_score, (int, float)) else str(s_score)
    llm_called = "YES" if record.get("llm_called") else "NO (Rule Gate / FAST_TRACK)"

    soc = record.get("soc_result") or {}
    outcome = str(soc.get("outcome", disposition)).upper()

    # Evidence details
    evidence = record.get("evidence") or {}
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            evidence = {}

    logs = evidence.get("logs") or {}
    flows = evidence.get("flows") or []

    # MITRE ATT&CK
    mitre_list = record.get("mitre") or []

    playbooks = generate_containment_playbook(record)

    md = [
        f"# 🛡️ Incident Investigation Report: {incident_id}",
        "",
        f"> **Generated by INTRUSCAN Autonomous SOC Agent** | Date: {recorded_at}",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Incident ID:** `{incident_id}`",
        f"- **Threat Priority:** **{priority}**",
        f"- **Triage Outcome:** **`{outcome}`** (Disposition: `{disposition}`)",
        f"- **Primary Suspect Source:** `{src}`",
        f"- **Target Destination:** `{dst}`",
        f"- **Routing Decision:** `{route}` (Fast Brain Anomaly Score: `{score_str}`)",
        f"- **Tier-2 LLM Escalation:** `{llm_called}`",
        "",
        "### Key Triage Reasoning",
        "",
    ]

    reasons = record.get("reasons") or []
    if reasons:
        for r in reasons:
            md.append(f"- `{r}`")
    else:
        md.append("- No specific risk flags flagged.")

    md.extend([
        "",
        "---",
        "",
        "## 2. MITRE ATT&CK® Threat Mapping",
        "",
    ])

    if mitre_list:
        md.append("| Technique ID | Technique Name | Tactic | Semantic Match Confidence |")
        md.append("| :--- | :--- | :--- | :--- |")
        for m in mitre_list:
            tid = m.get("technique_id", "N/A")
            name = m.get("name", "N/A")
            tactics = m.get("tactics", "N/A")
            conf = m.get("confidence", 0.0)
            md.append(f"| **[{tid}](https://attack.mitre.org/techniques/{tid.replace('.', '/')})** | {name} | `{tactics}` | **{conf:.2%}** |")
    else:
        md.append("*(No specific ATT&CK technique candidates matched or FAST_TRACK volumetric containment)*")

    md.extend([
        "",
        "---",
        "",
        "## 3. Autonomous Agent Reasoning & Verifier Audit",
        "",
    ])

    if soc:
        md.append(f"- **Agent Outcome:** `{soc.get('outcome', 'N/A')}`")
        act = soc.get("action")
        if act:
            md.append(f"- **Authorized Action:** `{act.get('type')}` targeting `{act.get('target')}`")
        else:
            md.append("- **Authorized Action:** `None` (Containment not authorized or alert closed)")
        md.append(f"- **Deterministic Claim Verdicts:** `{', '.join(soc.get('verdicts') or ['NONE'])}`")
        md.append(f"- **Risk Gate Flags:** `{', '.join(soc.get('gate_flags') or ['CLEAN (No Gate Violations)'])}`")
        md.append(f"- **Inference / Verification Latency:** LLM: `{soc.get('llm_ms', 0):.1f} ms` | Verifier: `{soc.get('verify_ms', 0):.2f} ms`")

        steps = soc.get("tool_steps") or []
        if steps:
            md.append(f"\n### Autonomous Investigation Steps ({len(steps)} tool calls)")
            for i, step in enumerate(steps, 1):
                md.append(f"{i}. `{json.dumps(step)}`")
    else:
        rule_check = evidence.get("rule_check") or {}
        if rule_check:
            md.append("### FAST_TRACK Rule Verification")
            md.append(f"- **Rule Outcome:** `{rule_check.get('outcome', 'TRIGGERED')}`")
            flags = rule_check.get("gate_flags") or []
            md.append(f"- **Rule Gate Flags:** `{', '.join(flags) if flags else 'None (Consistent with High Priority)'}`")
            ctx = rule_check.get("source_context") or {}
            if ctx:
                md.append(f"- **Context:** `{', '.join(f'{k}={v}' for k, v in ctx.items())}`")
        else:
            md.append("*(No agentic trace stored for this incident)*")

    md.extend([
        "",
        "---",
        "",
        "## 4. Observed Evidence & Telemetry",
        "",
    ])

    if logs:
        md.append("### Relevant Host & Security Logs")
        for eid, text in logs.items():
            md.append(f"```text\n[{eid}]\n{text}\n```")

    if flows:
        md.append(f"### Associated Network Flows ({len(flows)} flows)")
        md.append("```json")
        md.append(json.dumps(flows[:5], indent=2))
        if len(flows) > 5:
            md.append(f"... and {len(flows) - 5} more flows")
        md.append("```")

    md.extend([
        "",
        "---",
        "",
        "## 5. Recommended Containment Playbook",
        "",
        "### Perimeter Firewall Block (Linux iptables)",
        "```bash",
        playbooks["iptables"],
        "```",
        "",
        "### Host Firewall Block (Ubuntu UFW)",
        "```bash",
        playbooks["ufw"],
        "```",
        "",
        "### SIEM Detection Rule (Sigma Format)",
        "```yaml",
        playbooks["sigma_rule"],
        "```",
        "",
        "---",
        "*Confidential - Internal SOC Operations Only*",
    ])

    return "\n".join(md)
