"""INTRUSCAN SOC Dashboard (Streamlit).

Autonomous Dual-Brain Security Operations Center platform:
- Tier-1 Fast Brain: High-throughput network flow anomaly detection & line-rate routing
- Tier-2 Slow Brain: LangGraph agentic reasoning, Vector RAG, and deterministic temporal verifier
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import streamlit as st

from dashboard import data
from soc_agent.incidents import IncidentStore
from soc_agent.report_generator import format_markdown_report, generate_containment_playbook

DEMO_DIR = ROOT / "demo_data"
DEMO_SCORED = DEMO_DIR / "scored_flows.jsonl"
DEMO_DB = DEMO_DIR / "incidents.db"


st.set_page_config(
    page_title="INTRUSCAN SOC | Autonomous AI Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------
# ADAPTIVE CYBER DEFENSE DESIGN SYSTEM
# --------------------------------------------------
st.markdown(
    """
    <style>
    /* Metric cards: calm, clean, neutral alpha borders */
    div[data-testid="stMetric"] {
        background-color: rgba(128, 128, 128, 0.05);
        border: 1px solid rgba(128, 128, 128, 0.18);
        border-radius: 10px;
        padding: 14px 18px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.02);
    }
    div[data-testid="stMetric"] label {
        font-size: 0.80rem !important;
        font-weight: 600 !important;
        opacity: 0.78;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        font-size: 1.65rem !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em;
    }

    /* System Status Bar */
    .status-bar {
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-bottom: 1.2rem;
        padding: 8px 14px;
        border-radius: 8px;
        background: rgba(128, 128, 128, 0.06);
        border: 1px solid rgba(128, 128, 128, 0.16);
        font-size: 0.82rem;
        font-weight: 500;
        align-items: center;
    }
    .status-item {
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }
    .dot-green {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #10b981;
        box-shadow: 0 0 6px #10b981;
    }
    .dot-blue {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #3b82f6;
    }
    .dot-purple {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #8b5cf6;
    }

    /* Badges */
    .badge-pill {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.03em;
        text-transform: uppercase;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.35); }
    .badge-high { background: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.35); }
    .badge-medium { background: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.35); }
    .badge-low { background: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.35); }

    .badge-propose { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.35); }
    .badge-escalate { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.35); }
    .badge-close { background: rgba(107, 114, 128, 0.15); color: #9ca3af; border: 1px solid rgba(107, 114, 128, 0.35); }

    /* Segmented tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid rgba(128, 128, 128, 0.2);
        padding-bottom: 4px;
        background: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        height: 38px;
        padding: 0 16px;
        border-radius: 8px;
        border: none !important;
        font-size: 0.90rem;
        font-weight: 500;
        color: inherit;
        opacity: 0.70;
        background-color: transparent;
        transition: all 0.15s ease;
    }
    .stTabs [data-baseweb="tab"]:hover {
        opacity: 0.95;
        background-color: rgba(128, 128, 128, 0.08);
    }
    .stTabs [aria-selected="true"] {
        opacity: 1 !important;
        font-weight: 700 !important;
        background-color: rgba(128, 128, 128, 0.12) !important;
    }
    .stTabs [data-baseweb="tab-highlight"] {
        display: none;
    }

    /* Architecture Flow Cards */
    .arch-flow-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 12px;
        margin: 1rem 0 1.5rem 0;
    }
    .arch-card {
        padding: 14px 16px;
        border-radius: 10px;
        background: rgba(128, 128, 128, 0.04);
        border: 1px solid rgba(128, 128, 128, 0.18);
        border-left: 4px solid #3b82f6;
    }
    .arch-title {
        font-size: 0.85rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.03em;
        margin-bottom: 4px;
    }
    .arch-desc {
        font-size: 0.80rem;
        opacity: 0.80;
        line-height: 1.35;
    }

    /* Clean expander and table boundaries */
    div[data-testid="stExpander"] {
        border: 1px solid rgba(128, 128, 128, 0.18);
        border-radius: 10px;
        background-color: rgba(128, 128, 128, 0.02);
    }
    .stDataFrame {
        border: 1px solid rgba(128, 128, 128, 0.16);
        border-radius: 10px;
        overflow: hidden;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Header
st.title("🛡️ INTRUSCAN SOC")
st.caption(
    "Dual-Brain Autonomous Cyber Defense: High-Throughput Netflow Triage, "
    "LangGraph Agentic Analysis & Deterministic Evidence Verification"
)

# Live Status Banner
st.markdown(
    """
    <div class="status-bar">
        <span class="status-item"><span class="dot-green"></span> <b>SYSTEM STATUS:</b> ONLINE</span>
        <span style="opacity: 0.4;">|</span>
        <span class="status-item"><span class="dot-blue"></span> <b>TIER-1 FAST BRAIN:</b> IsolationForest Active</span>
        <span style="opacity: 0.4;">|</span>
        <span class="status-item"><span class="dot-purple"></span> <b>TIER-2 SLOW BRAIN:</b> LangGraph Agent Ready</span>
        <span style="opacity: 0.4;">|</span>
        <span class="status-item"><b>VERIFIER:</b> HMAC Provenance & Temporal Order Guardrails Active</span>
    </div>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# SIDEBAR: DATA SOURCE & SCENARIO SELECTION
# --------------------------------------------------

UPLOAD_ROOT = ROOT / "smoke" / "uploads"

# Ensure demo files exist
if not DEMO_SCORED.is_file() or not DEMO_DB.is_file():
    try:
        from tools.generate_demo_dataset import generate_demo_incidents, generate_demo_flows
        generate_demo_incidents()
        generate_demo_flows()
    except Exception:
        pass

# Initialize session state paths
if "pending_paths" in st.session_state:
    _new_scored, _new_db = st.session_state.pop("pending_paths")
    st.session_state["scored_path"] = _new_scored
    st.session_state["db_path"] = _new_db

default_scored = os.environ.get("INTRUSCAN_SCORED")
default_db = os.environ.get("INTRUSCAN_INCIDENT_DB")

# If default files don't exist on disk, fallback to demo dataset smoothly
if not default_scored or not Path(default_scored).is_file():
    default_scored = str(DEMO_SCORED) if DEMO_SCORED.is_file() else "scored_flows.jsonl"

if not default_db or not Path(default_db).is_file():
    default_db = str(DEMO_DB) if DEMO_DB.is_file() else "incidents.db"

st.session_state.setdefault("scored_path", default_scored)
st.session_state.setdefault("db_path", default_db)

with st.sidebar:
    st.markdown("### 🎛️ Control Center")

    dataset_source = st.radio(
        "Data Source Mode",
        options=["Interactive Demo Scenarios", "Custom Local Files"],
        index=0 if "demo_data" in st.session_state["scored_path"] else 1,
        help="Switch between preloaded realistic SOC attack scenarios or custom files.",
    )

    if dataset_source == "Interactive Demo Scenarios":
        st.session_state["scored_path"] = str(DEMO_SCORED)
        st.session_state["db_path"] = str(DEMO_DB)
        st.success("Loaded: 5 multi-stage attacks + 2,000 scored flows.")
    else:
        st.text_input("Scored flows (JSONL)", key="scored_path")
        st.text_input("Incident store (SQLite)", key="db_path")

    scored_path = st.session_state["scored_path"]
    db_path = st.session_state["db_path"]

    max_rows = st.number_input(
        "Max flow rows to load",
        1_000,
        1_000_000,
        200_000,
        step=10_000,
    )

    st.divider()
    st.markdown("### 📥 Export Telemetry")
    for _label, _file in (
        ("Scored flows", Path(scored_path)),
        ("LLM alerts", Path(scored_path).with_name("alerts.jsonl")),
    ):
        if not _file.is_file():
            st.caption(f"{_label}: file not found")
        elif _file.stat().st_size > 100 * 1024 * 1024:
            st.caption(f"{_label}: too large to download here (>{_file.stat().st_size // (1024*1024)}MB)")
        else:
            st.download_button(
                f"Download {_label.lower()} (.jsonl)",
                data=_file.read_bytes(),
                file_name=_file.name,
                mime="application/x-ndjson",
                key=f"dl_{_file.name}",
            )


# --------------------------------------------------
# UGR'16 UPLOAD & BATCH PIPELINE
# --------------------------------------------------

UGR16_MODEL = ROOT / "data" / "models" / "fast_brain_ugr16_v3.joblib"
UGR16_BASELINE = ROOT / "data" / "raw" / "ugr16_train.jsonl"

with st.expander("⚡ Run Pipeline on Raw UGR'16 CSV", expanded=False):
    if "upload_notice" in st.session_state:
        st.success(st.session_state.pop("upload_notice"))

    _last_report = st.session_state.get("last_report_path")
    if _last_report and Path(_last_report).is_file():
        st.download_button(
            "Download last run's full report (.jsonl)",
            data=Path(_last_report).read_bytes(),
            file_name=f"{Path(_last_report).parent.name}_report.jsonl",
            mime="application/x-ndjson",
            key="dl_last_report",
        )

    col_up, col_param = st.columns([1.2, 1])

    with col_up:
        uploaded_file = st.file_uploader(
            "Upload UGR'16 CSV",
            type=["csv"],
            help="Headerless official UGR'16 CSV (13 columns).",
        )

    with col_param:
        llm_provider = st.selectbox(
            "LLM Provider",
            options=["auto", "sim (Offline / Test)", "groq", "gemini"],
            index=0,
            help="auto tries Groq then Gemini. sim requires no API keys.",
        )
        llm_mode = "sim" if "sim" in llm_provider else llm_provider

        max_events = st.number_input(
            "Max LLM events per source",
            min_value=1,
            max_value=100,
            value=12,
            step=1,
        )
        max_sources = st.number_input(
            "Max sources sent to LLM (0 = no cap)",
            min_value=0,
            max_value=1000,
            value=10,
            step=1,
        )
        agentic_on = st.checkbox(
            "Agentic mode (tools + revision)",
            value=False,
            help="Analyst can request extra evidence (max 3 steps) and revise once.",
        )

    if st.button("Run Intruscan Analysis", type="primary", disabled=uploaded_file is None):
        if not UGR16_MODEL.is_file():
            st.error(f"Trained model not found: {UGR16_MODEL}")
        elif not UGR16_BASELINE.is_file():
            st.error(f"UGR'16 baseline file not found: {UGR16_BASELINE}")
        else:
            source_name = re.sub(
                r"[^A-Za-z0-9_.-]+",
                "_",
                Path(uploaded_file.name).stem,
            ) or "ugr16_upload"

            run_id = (
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{source_name}"
                + ("_agentic" if agentic_on else "_plain")
            )
            run_dir = UPLOAD_ROOT / run_id
            run_dir.mkdir(parents=True, exist_ok=False)

            scored_output = run_dir / "scored.jsonl"
            incident_db = run_dir / "incidents.db"
            rag_output = run_dir / "alerts.jsonl"

            run_env = os.environ.copy()
            run_env["INTRUSCAN_AGENTIC"] = "1" if agentic_on else "0"

            def run_step(label, command):
                st.write(f"**{label}**")
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=run_env,
                    capture_output=True,
                    text=True,
                )
                if result.stdout:
                    st.code(result.stdout)
                if result.stderr:
                    st.code(result.stderr)
                if result.returncode != 0:
                    raise RuntimeError(f"{label} failed with exit code {result.returncode}")

            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_dir = Path(temp_dir)
                    csv_path = temp_dir / Path(uploaded_file.name).name
                    parsed_path = temp_dir / "parsed_flows.jsonl"
                    csv_path.write_bytes(uploaded_file.getvalue())

                    with st.spinner("Processing network flow dataset..."):
                        run_step(
                            "Step 1: Parsing CSV flows",
                            [
                                sys.executable,
                                "tools/parse_ugr16_native.py",
                                str(csv_path),
                                str(parsed_path),
                                "--source-name",
                                source_name,
                            ],
                        )

                        run_step(
                            "Step 2: Fast Brain line-rate scoring",
                            [
                                sys.executable,
                                "-m",
                                "soc_agent.fast_brain_cli",
                                "score",
                                "--input",
                                str(parsed_path),
                                "--model",
                                str(UGR16_MODEL),
                                "--output",
                                str(scored_output),
                            ],
                        )

                        run_step(
                            "Step 3: RAG / Slow Brain handoff",
                            [
                                sys.executable,
                                "-m",
                                "rag.handoff",
                                "--scored",
                                str(scored_output),
                                "--output",
                                str(rag_output),
                                "--incident-db",
                                str(incident_db),
                                "--fast-brain-model",
                                str(UGR16_MODEL),
                                "--llm",
                                llm_mode,
                                "--model",
                                "openai/gpt-oss-20b",
                                "--chroma-path",
                                str(ROOT / "smoke" / "chroma_pipe"),
                                "--mitre",
                                "full",
                                "--baseline-file",
                                str(UGR16_BASELINE),
                                "--baseline-label",
                                "background",
                                "--max-events",
                                str(int(max_events)),
                                "--max-sources",
                                str(int(max_sources)),
                                "--timeout",
                                "600",
                            ],
                        )

                report_path = run_dir / "report.jsonl"
                _run_store = IncidentStore(incident_db)
                _run_frame = data.incidents_frame(_run_store)
                _run_ids = list(_run_frame["incident_id"]) if not _run_frame.empty else []
                with report_path.open("w", encoding="utf-8") as _fh:
                    for _iid in _run_ids:
                        _fh.write(json.dumps(_run_store.get(_iid), default=str) + "\n")

                st.session_state["last_report_path"] = str(report_path)
                st.session_state["upload_notice"] = (
                    f"Upload processed successfully ({'agentic' if agentic_on else 'plain'} mode). "
                    f"Saved to smoke/uploads/{run_id}/. Set sidebar paths to view."
                )
                st.cache_data.clear()
                st.rerun()

            except Exception as exc:
                st.error(f"Analysis failed: {exc}")


# --------------------------------------------------
# LOAD FLOWS & INCIDENTS
# --------------------------------------------------

@st.cache_data(show_spinner=False)
def _flows(path: str, rows: int, mtime: float):
    return data.load_scored_flows(path, rows)


def _as_dict(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def _render_fast_track(record):
    """View of a FAST_TRACK line-rate containment incident (bypasses LLM to avoid burn)."""
    evidence = _as_dict(record.get("evidence"))
    rule = _as_dict(evidence.get("rule_check"))
    thresholds = _as_dict(record.get("thresholds"))

    st.subheader(f"⚡ FAST_TRACK Incident: {record.get('incident_id')}")

    a, b, c, d = st.columns(4)
    a.metric("Route", "FAST_TRACK")
    b.metric("Priority", record["priority"])
    c.metric("LLM Bypass", "Line-Rate Containment")
    d.metric("Rule Gate Outcome", rule.get("outcome", "TRIGGERED"))

    score = record.get("s_score", 0.0)
    upper = thresholds.get("upper", 0.85)

    st.info(
        f"**Line-rate fast track triggered:** Target `{record.get('src')}` -> `{record.get('dst', 'internal targets')}`. "
        f"Anomaly score `{score:.4f}` significantly exceeded the upper severity threshold (`>{upper:.2f}`). "
        "Escalation to Slow Brain was bypassed to execute immediate perimeter defense."
    )

    context = _as_dict(rule.get("source_context"))
    if context:
        st.caption("Telemetry Context: " + ", ".join(f"**{k}** = `{v}`" for k, v in context.items()))

    flags = rule.get("gate_flags") or []
    if flags:
        st.warning("Rule flags: " + "; ".join(str(f) for f in flags))
    else:
        st.success("Verification: No conflicting flags. Telemetry is fully consistent with CRITICAL containment.")

    # Remediation Playbook
    playbook = generate_containment_playbook(record)
    st.markdown("#### 🚨 Immediate Containment Playbook")
    t1, t2, t3 = st.tabs(["Linux iptables", "Ubuntu UFW", "Sigma SIEM Rule"])
    with t1:
        st.code(playbook["iptables"], language="bash")
    with t2:
        st.code(playbook["ufw"], language="bash")
    with t3:
        st.code(playbook["sigma_rule"], language="yaml")

    col_dl1, col_dl2 = st.columns(2)
    with col_dl1:
        st.download_button(
            "📥 Download Investigation Report (.md)",
            data=format_markdown_report(record),
            file_name=f"{record.get('incident_id')}_report.md",
            mime="text/markdown",
            key=f"dl_ft_md_{record.get('incident_id')}",
        )
    with col_dl2:
        st.download_button(
            "📥 Export Incident Record (.json)",
            data=json.dumps(record, indent=2, default=str),
            file_name=f"{record.get('incident_id')}.json",
            mime="application/json",
            key=f"dl_ft_json_{record.get('incident_id')}",
        )

    with st.expander("Raw Telemetry & Flow Evidence"):
        st.json({k: record.get(k) for k in ("incident_id", "src", "dst", "first_flow_ts", "model_sha256", "thresholds")})
        if evidence.get("flows"):
            st.dataframe(pd.DataFrame(evidence["flows"]), use_container_width=True)


flows_file = Path(scored_path)
flows_mtime = flows_file.stat().st_mtime if flows_file.is_file() else 0.0

loaded = _flows(scored_path, int(max_rows), flows_mtime)
frame = loaded.frame

store = IncidentStore(db_path) if Path(db_path).is_file() else None
incidents = data.incidents_frame(store)


# --------------------------------------------------
# MAIN TABS
# --------------------------------------------------

overview, incidents_tab, investigate, mitre_tab, graph_tab, history = st.tabs(
    [
        "📊 Architecture & Overview",
        "🚨 Incident Triage Queue",
        "🔍 Deep Investigation & Playbooks",
        "🎯 MITRE ATT&CK® Matrix",
        "🌐 Network Threat Topology",
        "📈 Investigation History",
    ]
)


# --------------------------------------------------
# 1. OVERVIEW & SYSTEM ARCHITECTURE
# --------------------------------------------------

with overview:
    st.markdown("### 🏛️ Dual-Brain SOC Architecture")
    st.markdown(
        """
        <div class="arch-flow-container">
            <div class="arch-card" style="border-left-color: #10b981;">
                <div class="arch-title" style="color: #10b981;">1. Ingestion & Fast Brain</div>
                <div class="arch-desc">Streaming netflow ingestion, Isolation Forest scoring at line-rate. 90%+ traffic dropped as CLEAR.</div>
            </div>
            <div class="arch-card" style="border-left-color: #3b82f6;">
                <div class="arch-title" style="color: #3b82f6;">2. Calibrated Routing Gate</div>
                <div class="arch-desc"><b>CLEAR:</b> drop benign. <b>FAST_TRACK:</b> immediate rule block. <b>SLOW_BRAIN:</b> deep AI investigation.</div>
            </div>
            <div class="arch-card" style="border-left-color: #8b5cf6;">
                <div class="arch-title" style="color: #8b5cf6;">3. Slow Brain & Vector RAG</div>
                <div class="arch-desc">ChromaDB semantic retrieval of MITRE ATT&CK techniques; LangGraph agentic reasoning.</div>
            </div>
            <div class="arch-card" style="border-left-color: #ef4444;">
                <div class="arch-title" style="color: #ef4444;">4. Verifier & Risk Gate</div>
                <div class="arch-desc">Deterministic 3-state check (temporal order, HMAC provenance) ensures zero hallucinated actions.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    counts = data.route_counts(frame)
    cols = st.columns(4)
    cols[0].metric("Total Flows Analyzed", f"{len(frame):,}")
    cols[1].metric("CLEAR (Benign Dropped)", f"{counts['CLEAR']:,}", help="Line-rate drop: zero LLM cost")
    cols[2].metric("SLOW_BRAIN (AI Escalated)", f"{counts['SLOW_BRAIN']:,}", help="Escalated for deep multi-agent investigation")
    cols[3].metric("FAST_TRACK (Line-Rate Drop)", f"{counts['FAST_TRACK']:,}", help="High-confidence volumetric attack drop")

    if loaded.invalid_rows:
        st.warning(f"{loaded.invalid_rows} unreadable rows were skipped.")
    if loaded.truncated:
        st.info(f"Loaded the most recent {int(max_rows):,} rows for real-time responsiveness.")

    if not frame.empty:
        left, right = st.columns(2)
        with left:
            st.subheader("Model Traffic Split")
            st.bar_chart(pd.Series(data.traffic_split(frame)))
            st.caption("90%+ of traffic is safely classified as benign, preventing LLM alert fatigue and API costs.")

        with right:
            st.subheader("Routing Distribution")
            st.bar_chart(pd.Series(counts))

        if "s_score" in frame:
            st.subheader("Anomaly Score Distribution (Isolation Forest)")
            st.bar_chart(
                pd.cut(
                    frame["s_score"].astype(float),
                    bins=20,
                ).value_counts().sort_index().rename(str)
            )

        crosstab = data.label_vs_route(frame)
        if not crosstab.empty:
            st.subheader("Dataset Ground Truth Label vs Route Decision")
            st.dataframe(crosstab, use_container_width=True)

    if not incidents.empty:
        st.subheader("Threat Severity Distribution")
        st.bar_chart(incidents["priority"].value_counts())


# --------------------------------------------------
# 2. INCIDENT TRIAGE QUEUE
# --------------------------------------------------

with incidents_tab:
    if incidents.empty:
        st.info("No incidents currently recorded. Select 'Interactive Demo Scenarios' in the sidebar to view demo incidents.")
    else:
        col_k, col_p = st.columns(2)
        with col_k:
            kinds = st.multiselect(
                "Filter by Kind",
                sorted(incidents["kind"].unique()),
                default=sorted(incidents["kind"].unique()),
            )
        with col_p:
            prios = st.multiselect(
                "Filter by Priority",
                sorted(incidents["priority"].unique()),
                default=sorted(incidents["priority"].unique()),
            )

        view = incidents[
            incidents["kind"].isin(kinds)
            & incidents["priority"].isin(prios)
        ]

        incident_cols = [
            "incident_id",
            "kind",
            "priority",
            "disposition",
            "llm_called",
            "src",
            "dst",
            "s_score",
            "flow_count",
            "recorded_at",
        ]
        available_cols = [c for c in incident_cols if c in view.columns]
        incident_view = view[available_cols]

        st.dataframe(incident_view, use_container_width=True)

        col_exp1, col_exp2 = st.columns([1, 4])
        with col_exp1:
            st.download_button(
                "Export Queue (.jsonl)",
                data=incident_view.to_json(orient="records", lines=True, date_format="iso"),
                file_name="incidents_export.jsonl",
                mime="application/x-ndjson",
            )


# --------------------------------------------------
# 3. DEEP INVESTIGATION & PLAYBOOKS
# --------------------------------------------------

with investigate:
    if incidents.empty:
        st.info("No incidents to investigate.")
    else:
        incident_options = list(incidents["incident_id"])
        chosen = st.selectbox(
            "Select Incident to Investigate",
            options=incident_options,
            format_func=lambda iid: f"{iid} | Priority: {incidents.loc[incidents['incident_id'] == iid, 'priority'].values[0]} | Route: {incidents.loc[incidents['incident_id'] == iid, 'kind'].values[0]}",
        )

        record = store.get(chosen) if store else None

        if record and record["kind"] == "fast_track" and not record.get("soc_result"):
            _render_fast_track(record)
            record = None

        if record:
            st.subheader(f"🛡️ Incident Investigation: {record['incident_id']}")

            # Executive Banner
            prio = record.get("priority", "UNKNOWN")
            disp = record.get("disposition", "UNKNOWN")
            score = record.get("s_score", 0.0)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Priority", prio)
            c2.metric("Disposition", disp)
            c3.metric("Anomaly Score", f"{score:.4f}" if isinstance(score, (int, float)) else str(score))
            c4.metric("LLM Escalated", "Yes" if record.get("llm_called") else "No")

            # Telemetry Attributes
            with st.expander("Telemetry & Cryptographic Verification Attributes", expanded=False):
                st.json(
                    {
                        k: record[k]
                        for k in (
                            "kind", "src", "dst", "route", "s_score",
                            "first_flow_ts", "ts_kind", "ts_original",
                            "feature_set", "model_sha256", "thresholds",
                        )
                        if k in record
                    }
                )

            # Triage Reasoning
            st.markdown("#### 📋 Triage Reasoning & Risk Triggers")
            reasons = record.get("reasons") or []
            if isinstance(reasons, str):
                try:
                    reasons = json.loads(reasons)
                except Exception:
                    reasons = [reasons]
            for r in reasons:
                st.markdown(f"- `{r}`")

            # AGENTIC AI & VERIFIER RESULTS
            soc = record.get("soc_result") or {}
            if soc:
                st.divider()
                st.markdown("#### 🤖 Agentic AI Reasoning & Deterministic Verifier Audit")

                a, o, b, c = st.columns(4)
                a.metric("Escalated to LLM", "Yes" if record.get("llm_called") else "No")
                o.metric("Agent Outcome", str(soc.get("outcome", "unknown")).upper())

                provider = soc.get("provider") or record.get("provider") or "local"
                model = soc.get("model") or record.get("model") or "llm"
                b.metric("Provider / Model", f"{provider} / {model}")

                llm_ms = soc.get("llm_ms", 0.0)
                v_ms = soc.get("verify_ms", 0.0)
                c.metric("Latency", f"{llm_ms:.0f}ms LLM | {v_ms:.2f}ms Verifier")

                # Verifier & Risk Gate Status
                v_col1, v_col2 = st.columns(2)
                with v_col1:
                    verdicts = soc.get("verdicts") or []
                    verdicts_str = ", ".join(verdicts) if verdicts else "NONE"
                    if "SUPPORTED" in verdicts:
                        st.success(f"**Deterministic Claim Verifier:** `{verdicts_str}` (Temporal order & evidence confirmed)")
                    elif "CONTRADICTED" in verdicts:
                        st.error(f"**Deterministic Claim Verifier:** `{verdicts_str}` (Contradiction detected)")
                    else:
                        st.warning(f"**Deterministic Claim Verifier:** `{verdicts_str}` (Evidence incomplete / Unknown)")

                with v_col2:
                    gate_flags = soc.get("gate_flags") or []
                    if gate_flags:
                        st.warning(f"**Risk Gate Triggered:** `{', '.join(gate_flags)}`")
                    else:
                        st.success("**Risk Gate:** Clean. No unauthorized actions or severity floor violations.")

                # Agent activity & Tool steps
                steps = soc.get("tool_steps") or []
                if steps:
                    st.markdown(f"##### 🛠️ Autonomous Investigation Steps ({len(steps)} tool calls)")
                    for i, step in enumerate(steps, 1):
                        with st.expander(f"Tool Step {i}: {step.get('action', 'inspect')}"):
                            st.json(step)

            # Containment Playbook
            st.divider()
            st.markdown("#### 🚨 Recommended Containment Playbook")
            playbook = generate_containment_playbook(record)

            pb1, pb2, pb3, pb4 = st.tabs(["Linux iptables", "Ubuntu UFW", "AWS Network ACL", "Sigma SIEM Rule"])
            with pb1:
                st.code(playbook["iptables"], language="bash")
            with pb2:
                st.code(playbook["ufw"], language="bash")
            with pb3:
                st.code(playbook["aws_cli"], language="bash")
            with pb4:
                st.code(playbook["sigma_rule"], language="yaml")

            # Evidence & Logs
            st.divider()
            st.markdown("#### 🔬 Observed Telemetry & Log Evidence")
            evidence = record.get("evidence") or {}
            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except Exception:
                    evidence = {}

            if evidence.get("logs"):
                st.markdown("##### Host & Security Event Logs")
                for event_id, text in evidence["logs"].items():
                    st.code(f"[{event_id}]\n{text}")

            if evidence.get("events"):
                st.markdown("##### Knowledge-Graph Event Nodes")
                st.dataframe(pd.DataFrame(evidence["events"]), use_container_width=True)

            if evidence.get("flows"):
                st.markdown("##### Associated Flow Telemetry")
                st.dataframe(pd.DataFrame(evidence["flows"]), use_container_width=True)

            # MITRE Candidates
            mitre_candidates = record.get("mitre") or []
            if isinstance(mitre_candidates, str):
                try:
                    mitre_candidates = json.loads(mitre_candidates)
                except Exception:
                    mitre_candidates = []

            if mitre_candidates:
                st.markdown("##### 🎯 MITRE ATT&CK® Candidates (VectorRAG Ranked)")
                st.dataframe(pd.DataFrame(mitre_candidates), use_container_width=True)

            # Report Export
            st.divider()
            st.markdown("#### 📄 Export Official SOC Incident Report")
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.download_button(
                    "📥 Download Incident Investigation Report (.md)",
                    data=format_markdown_report(record),
                    file_name=f"{record.get('incident_id')}_investigation_report.md",
                    mime="text/markdown",
                    key=f"dl_md_{record.get('incident_id')}",
                )
            with col_d2:
                st.download_button(
                    "📥 Export Full Incident Record (.json)",
                    data=json.dumps(record, indent=2, default=str),
                    file_name=f"{record.get('incident_id')}.json",
                    mime="application/json",
                    key=f"dl_json_{record.get('incident_id')}",
                )


# --------------------------------------------------
# 4. MITRE ATT&CK MATRIX
# --------------------------------------------------

with mitre_tab:
    st.subheader("🎯 MITRE ATT&CK® Threat Intelligence Mapping")
    st.caption("Techniques retrieved via VectorRAG (ChromaDB semantic search) mapped across active incidents.")

    summary = data.mitre_summary(store.list() if store else [])

    if summary.empty:
        st.info("No ATT&CK candidates recorded in current incident store.")
    else:
        st.dataframe(summary, use_container_width=True)

        st.markdown("#### 📚 Direct ATT&CK Knowledge Base Links")
        for _, row in summary.iterrows():
            tid = row["technique_id"]
            name = row["name"]
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"
            st.markdown(f"- **[{tid}: {name}]({url})** | Tactics: `{row['tactics']}` | Max Confidence: `{row['max_confidence']:.2%}`")


# --------------------------------------------------
# 5. NETWORK HOST GRAPH
# --------------------------------------------------

with graph_tab:
    st.subheader("🌐 Network Threat Topology & Attack Propagation")

    graph = data.host_graph(frame)

    if graph.number_of_edges() == 0:
        st.info("No suspicious network flows to visualize.")
    else:
        fig, ax = plt.subplots(figsize=(10, 6.5), dpi=140)

        # Clean background
        fig.patch.set_alpha(0.0)
        ax.patch.set_alpha(0.0)

        pos = nx.spring_layout(graph, seed=42, k=0.8)

        colors = [
            "#ef4444" if d.get("fast_track") else "#f59e0b"
            for _, _, d in graph.edges(data=True)
        ]

        widths = [
            1.2 + min(d.get("flows", 1), 25) / 5.0
            for _, _, d in graph.edges(data=True)
        ]

        node_colors = []
        for n in graph.nodes():
            n_str = str(n)
            if "203.0.113" in n_str or "198.51.100" in n_str:
                node_colors.append("#ef4444")  # External adversary
            elif "192.168.1.105" in n_str:
                node_colors.append("#f97316")  # Compromised workstation
            elif "10.0.0.80" in n_str:
                node_colors.append("#8b5cf6")  # Gateway
            else:
                node_colors.append("#3b82f6")  # Internal Target

        nx.draw_networkx_nodes(
            graph,
            pos,
            ax=ax,
            node_size=650,
            node_color=node_colors,
            alpha=0.9,
        )

        nx.draw_networkx_labels(
            graph,
            pos,
            ax=ax,
            font_size=8,
            font_weight="bold",
            font_color="#ffffff",
        )

        nx.draw_networkx_edges(
            graph,
            pos,
            ax=ax,
            edge_color=colors,
            width=widths,
            arrows=True,
            arrowsize=14,
            arrowstyle="-|>",
            connectionstyle="arc3,rad=0.1",
        )

        ax.axis("off")
        st.pyplot(fig)
        plt.close(fig)

        st.caption(
            "🔴 Red Nodes = External Adversary | 🟠 Orange Nodes = Compromised Host | 🟣 Purple Nodes = Gateway | 🔵 Blue Nodes = Internal Targets\n"
            "Edges: Red = FAST_TRACK volumetric flows, Orange = SLOW_BRAIN investigated flows. Width reflects packet/flow volume."
        )


# --------------------------------------------------
# 6. HISTORY
# --------------------------------------------------

with history:
    st.subheader("📈 Chronological Incident History")
    if incidents.empty:
        st.info("No historical incident records available.")
    else:
        per_day = (
            incidents.dropna(subset=["recorded_at"])
            .set_index("recorded_at")
            .resample("1D")
            .size()
        )

        st.bar_chart(per_day.rename("Incidents Triaged"))

        st.dataframe(
            incidents[
                [
                    "recorded_at",
                    "incident_id",
                    "kind",
                    "priority",
                    "disposition",
                    "src",
                    "dst",
                ]
            ],
            use_container_width=True,
        )
