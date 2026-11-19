"""INTRUSCAN SOC dashboard (Streamlit)."""

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


st.set_page_config(
    page_title="INTRUSCAN SOC",
    layout="wide",
)

# --------------------------------------------------
# ADAPTIVE DESIGN SYSTEM (Light & Dark Mode Compatible)
# --------------------------------------------------
st.markdown(
    """
    <style>
    /* Metric cards: calm, clean, neutral alpha borders */
    div[data-testid="stMetric"] {
        background-color: rgba(128, 128, 128, 0.04);
        border: 1px solid rgba(128, 128, 128, 0.18);
        border-radius: 8px;
        padding: 14px 18px;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
    }
    div[data-testid="stMetric"] label {
        font-size: 0.78rem !important;
        font-weight: 500 !important;
        opacity: 0.72;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        font-size: 1.55rem !important;
        font-weight: 600 !important;
        letter-spacing: -0.02em;
    }

    /* Segmented tabs: clean and unobtrusive in both light & dark */
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        border-bottom: 1px solid rgba(128, 128, 128, 0.2);
        padding-bottom: 3px;
        background: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        height: 36px;
        padding: 0 14px;
        border-radius: 6px;
        border: none !important;
        font-size: 0.88rem;
        font-weight: 500;
        color: inherit;
        opacity: 0.65;
        background-color: transparent;
        transition: all 0.15s ease;
    }
    .stTabs [data-baseweb="tab"]:hover {
        opacity: 0.95;
        background-color: rgba(128, 128, 128, 0.08);
    }
    .stTabs [aria-selected="true"] {
        opacity: 1 !important;
        font-weight: 600 !important;
        background-color: rgba(128, 128, 128, 0.12) !important;
    }
    .stTabs [data-baseweb="tab-highlight"] {
        display: none;
    }

    /* Clean typography & headings */
    h1 {
        font-weight: 700 !important;
        letter-spacing: -0.025em !important;
        margin-bottom: 0.2rem !important;
    }
    h2, h3 {
        font-weight: 600 !important;
        letter-spacing: -0.02em !important;
    }

    /* Clean expander and table boundaries */
    div[data-testid="stExpander"] {
        border: 1px solid rgba(128, 128, 128, 0.18);
        border-radius: 8px;
        background-color: rgba(128, 128, 128, 0.02);
    }
    .stDataFrame {
        border: 1px solid rgba(128, 128, 128, 0.16);
        border-radius: 8px;
        overflow: hidden;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Clean, authentic page header
st.title("INTRUSCAN SOC")
st.caption("Network flow anomaly triage & incident investigation platform")


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

UPLOAD_ROOT = ROOT / "smoke" / "uploads"

# An upload run asks for its new files to be shown by leaving them here;
# they are applied before the sidebar widgets are created
if "pending_paths" in st.session_state:
    _new_scored, _new_db = st.session_state.pop("pending_paths")
    st.session_state["scored_path"] = _new_scored
    st.session_state["db_path"] = _new_db

st.session_state.setdefault(
    "scored_path", os.environ.get("INTRUSCAN_SCORED", "scored_flows.jsonl")
)
st.session_state.setdefault(
    "db_path", os.environ.get("INTRUSCAN_INCIDENT_DB", "incidents.db")
)

with st.sidebar:
    st.subheader("Data sources")

    scored_path = st.text_input("Scored flows (JSONL)", key="scored_path")

    db_path = st.text_input("Incident store (SQLite)", key="db_path")

    max_rows = st.number_input(
        "Max flow rows to load",
        1_000,
        1_000_000,
        200_000,
        step=10_000,
    )

    st.caption("Refresh the page (or press R) to re-read the files.")

    st.divider()
    st.subheader("Export (JSONL)")
    for _label, _file in (
        ("Scored flows", Path(scored_path)),
        ("LLM alerts", Path(scored_path).with_name("alerts.jsonl")),
    ):
        if not _file.is_file():
            st.caption(f"{_label}: file not found")
        elif _file.stat().st_size > 100 * 1024 * 1024:
            st.caption(f"{_label}: too large to download here, use {_file}")
        else:
            st.download_button(
                f"Download {_label.lower()} (.jsonl)",
                data=_file.read_bytes(),
                file_name=_file.name,
                mime="application/x-ndjson",
                key=f"dl_{_file.name}",
            )


# --------------------------------------------------
# UGR'16 UPLOAD
# --------------------------------------------------

UGR16_MODEL = ROOT / "data" / "models" / "fast_brain_ugr16_v3.joblib"
UGR16_BASELINE = ROOT / "data" / "raw" / "ugr16_train.jsonl"

with st.expander("Upload a UGR'16 CSV and run analysis", expanded=False):
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
        max_events = st.number_input(
            "Max LLM events per source",
            min_value=1,
            max_value=100,
            value=12,
            step=1,
        )
        max_sources = st.number_input(
            "Max sources sent to the LLM (0 = no cap)",
            min_value=0,
            max_value=1000,
            value=10,
            step=1,
        )
        agentic_on = st.checkbox(
            "Agentic mode (tools + revision)",
            value=False,
            help="Analyst can request extra evidence (max 3 steps) and revise "
            "once. Slower: about 3 to 5 LLM calls per source.",
        )

    if st.button(
        "Run Intruscan analysis",
        type="primary",
        disabled=uploaded_file is None,
    ):
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

            # The agent reads INTRUSCAN_AGENTIC when it starts; subprocesses
            # inherit this environment, so the checkbox controls the run.
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
                    raise RuntimeError(
                        f"{label} failed with exit code {result.returncode}"
                    )

            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_dir = Path(temp_dir)

                    csv_path = temp_dir / Path(uploaded_file.name).name
                    parsed_path = temp_dir / "parsed_flows.jsonl"

                    csv_path.write_bytes(uploaded_file.getvalue())

                    with st.spinner("Processing uploaded dataset..."):
                        run_step(
                            "Step 1: Parsing CSV",
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
                            "Step 2: Fast Brain scoring",
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
                                "auto",
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

                # Full per-incident report for later use
                report_path = run_dir / "report.jsonl"
                _run_store = IncidentStore(incident_db)
                _run_frame = data.incidents_frame(_run_store)
                _run_ids = (
                    list(_run_frame["incident_id"]) if not _run_frame.empty else []
                )
                with report_path.open("w", encoding="utf-8") as _fh:
                    for _iid in _run_ids:
                        _fh.write(
                            json.dumps(_run_store.get(_iid), default=str) + "\n"
                        )

                st.session_state["last_report_path"] = str(report_path)
                st.session_state["upload_notice"] = (
                    f"Upload processed ({'agentic' if agentic_on else 'plain'} "
                    f"mode). Files are saved in smoke/uploads/{run_id}/ "
                    "(scored.jsonl, alerts.jsonl, incidents.db, report.jsonl). "
                    "The sidebar was not changed. To view this run, set the "
                    "sidebar paths to its scored.jsonl and incidents.db."
                )
                st.cache_data.clear()
                st.rerun()

            except Exception as exc:
                st.error(
                    f"Analysis failed: {exc}. Partial files (if any) are in "
                    f"smoke/uploads/{run_id}/ ; your other files were not changed."
                )


# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------


# If this line ever raises a pickling error, delete the decorator.
@st.cache_data(show_spinner=False)
def _flows(path: str, rows: int, mtime: float):
    return data.load_scored_flows(path, rows)


def _as_dict(value):
    """Stored JSON columns may arrive as dicts or as JSON strings."""
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
    """Compact view of a FAST_TRACK incident (no LLM is called for these)."""
    evidence = _as_dict(record.get("evidence"))
    rule = _as_dict(evidence.get("rule_check"))
    thresholds = _as_dict(record.get("thresholds"))

    st.subheader("FAST_TRACK incident")

    a, b, c, d = st.columns(4)
    a.metric("Route", "FAST_TRACK")
    b.metric("Priority", record["priority"])
    c.metric("LLM", "not called")
    d.metric("Rule check", rule.get("outcome", "n/a"))

    # one-line evidence summary
    score = record.get("s_score")
    upper = thresholds.get("upper")
    parts = [f"source {record.get('src')}"]
    context = _as_dict(rule.get("source_context"))
    if context:
        st.caption(
            "Source context: "
            + ", ".join(f"{k} = {v}" for k, v in context.items())
        )

    # rule gate
    flags = rule.get("gate_flags") or []
    if flags:
        st.warning("Rule flags: " + "; ".join(str(f) for f in flags))
    elif rule:
        st.success("No rule flags: evidence is consistent with HIGH priority.")
    else:
        st.info("No rule check stored for this incident.")

    with st.expander("Details (flows, record fields, full rule check)"):
        st.write(
            {
                k: record.get(k)
                for k in (
                    "incident_id",
                    "src",
                    "dst",
                    "first_flow_ts",
                    "feature_set",
                    "model_sha256",
                    "thresholds",
                )
            }
        )
        if evidence.get("flows"):
            st.dataframe(
                pd.DataFrame(evidence["flows"]),
                use_container_width=True,
            )
        if rule:
            st.json(rule)


flows_file = Path(scored_path)
flows_mtime = (
    flows_file.stat().st_mtime
    if flows_file.is_file()
    else 0.0
)

loaded = _flows(scored_path, int(max_rows), flows_mtime)
frame = loaded.frame

store = (
    IncidentStore(db_path)
    if Path(db_path).is_file()
    else None
)

incidents = data.incidents_frame(store)

if frame.empty and incidents.empty:
    st.info(
        "No data yet. Produce scored flows with "
        "`python -m soc_agent.fast_brain_cli score ... --output "
        f"{scored_path}` and incidents with the handoff tools' "
        f"`--incident-db {db_path}` option."
    )


# --------------------------------------------------
# DASHBOARD TABS
# --------------------------------------------------

overview, incidents_tab, investigate, mitre_tab, graph_tab, history = (
    st.tabs(
        [
            "Overview",
            "Incidents",
            "Investigation",
            "MITRE ATT&CK",
            "Host graph",
            "History",
        ]
    )
)


# --------------------------------------------------
# 1. OVERVIEW
# --------------------------------------------------

with overview:
    counts = data.route_counts(frame)

    cols = st.columns(4)
    cols[0].metric("Flows processed", f"{len(frame):,}")
    cols[1].metric("CLEAR", f"{counts['CLEAR']:,}")
    cols[2].metric("SLOW_BRAIN", f"{counts['SLOW_BRAIN']:,}")
    cols[3].metric("FAST_TRACK", f"{counts['FAST_TRACK']:,}")

    if loaded.invalid_rows:
        st.warning(f"{loaded.invalid_rows} unreadable rows were skipped.")

    if loaded.truncated:
        st.warning(f"Only the most recent {int(max_rows):,} rows are loaded.")

    if not frame.empty:
        left, right = st.columns(2)

        with left:
            st.subheader("Benign vs suspicious (model routing)")
            st.bar_chart(pd.Series(data.traffic_split(frame)))
            st.caption(
                "Suspicious = routed to SLOW_BRAIN or FAST_TRACK. "
                "Not a confirmed attack."
            )

        with right:
            st.subheader("Routing decisions")
            st.bar_chart(pd.Series(counts))

        if "s_score" in frame:
            st.subheader("Anomaly score distribution")
            st.bar_chart(
                pd.cut(
                    frame["s_score"].astype(float),
                    bins=20,
                ).value_counts().sort_index().rename(str)
            )

        crosstab = data.label_vs_route(frame)
        if not crosstab.empty:
            st.subheader("Dataset label vs route (ground truth, when present)")
            st.dataframe(crosstab, use_container_width=True)

        quality = data.timestamp_quality(frame)
        if set(quality) - {"absolute"}:
            st.warning(
                f"Timestamp quality: {quality}. "
                "Surrogate/missing timestamps are excluded from verification."
            )

    if not incidents.empty:
        st.subheader("Threat severity (incident priority)")
        st.bar_chart(incidents["priority"].value_counts())


# --------------------------------------------------
# 2. INCIDENTS
# --------------------------------------------------

with incidents_tab:
    if incidents.empty:
        st.write("No incidents recorded.")
    else:
        col_k, col_p = st.columns(2)
        with col_k:
            kinds = st.multiselect(
                "Kind",
                sorted(incidents["kind"].unique()),
                default=sorted(incidents["kind"].unique()),
            )
        with col_p:
            prios = st.multiselect(
                "Priority",
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
            "ts_kind",
            "recorded_at",
        ]
        available_cols = [c for c in incident_cols if c in view.columns]
        incident_view = view[available_cols]

        st.dataframe(incident_view, use_container_width=True)

        st.download_button(
            "Export incidents (.jsonl)",
            data=incident_view.to_json(
                orient="records", lines=True, date_format="iso"
            ),
            file_name="incidents.jsonl",
            mime="application/x-ndjson",
        )
        st.caption("Exports the rows shown above (after the Kind/Priority filters).")


# --------------------------------------------------
# 3. AGENTIC AI INVESTIGATION
# --------------------------------------------------

with investigate:
    if incidents.empty:
        st.write("No incidents recorded.")
    else:
        chosen = st.selectbox(
            "Incident",
            list(incidents["incident_id"]),
        )

        record = store.get(chosen) if store else None

        # FAST_TRACK incidents get the short panel and skip the long view
        if record and record["kind"] == "fast_track" and not record.get("soc_result"):
            _render_fast_track(record)
            record = None

        if record:
            a, b, c = st.columns(3)
            a.metric("Priority", record["priority"])
            b.metric("Disposition", record["disposition"])
            c.metric("LLM called", "yes" if record["llm_called"] else "no")

            st.subheader("Telemetry attributes")
            st.json(
                {
                    k: record[k]
                    for k in (
                        "kind",
                        "src",
                        "dst",
                        "route",
                        "s_score",
                        "first_flow_ts",
                        "ts_kind",
                        "ts_original",
                        "feature_set",
                        "model_sha256",
                        "thresholds",
                    )
                    if k in record
                }
            )

            st.subheader("Reasons")
            st.write(record["reasons"])

            # AGENTIC AI RESULTS
            soc = record.get("soc_result") or {}
            if soc:
                st.divider()
                st.subheader("Agentic AI Investigation")

                a, o, b, c = st.columns(4)
                a.metric("Escalated to LLM", "yes" if record["llm_called"] else "no")
                o.metric("Agent outcome", str(soc.get("outcome", "unknown")).upper())

                llm_used = " / ".join(
                    str(v)
                    for v in (
                        soc.get("provider") or record.get("provider"),
                        soc.get("model") or record.get("model"),
                    )
                    if v
                ) or "not recorded"
                b.metric("LLM used", llm_used)
                c.metric("LLM time", f"{soc.get('llm_ms', 0) / 1000:.1f} s")

                # Agent activity (only shown if the run stored these fields)
                steps = soc.get("tool_steps") or []
                if "tool_steps" in soc or "revised" in soc:
                    x, y = st.columns(2)
                    x.metric("Tool steps used", len(steps))
                    y.metric(
                        "Revised after verifier",
                        "yes" if soc.get("revised") else "no",
                    )
                    for i, step in enumerate(steps, 1):
                        with st.expander(f"Tool step {i}"):
                            st.write(step)

                with st.expander("Raw agent result (debug)"):
                    st.json(soc)
            else:
                st.info("No SOC agent result is stored for this incident.")

            # EVIDENCE
            st.divider()
            st.subheader("Evidence")

            evidence = record["evidence"]

            if evidence.get("logs"):
                for event_id, text in evidence["logs"].items():
                    st.code(f"[{event_id}]\n{text}")

            if evidence.get("events"):
                st.dataframe(pd.DataFrame(evidence["events"]), use_container_width=True)

            if evidence.get("flows"):
                st.dataframe(pd.DataFrame(evidence["flows"]), use_container_width=True)

            # MITRE DETAILS
            if record["mitre"]:
                st.subheader("ATT&CK candidates (similarity-ranked, not verdicts)")
                st.dataframe(pd.DataFrame(record["mitre"]), use_container_width=True)


# --------------------------------------------------
# 4. MITRE ATT&CK
# --------------------------------------------------

with mitre_tab:
    summary = data.mitre_summary(store.list() if store else [])

    if summary.empty:
        st.write("No ATT&CK candidates recorded (they come from the RAG handoff).")
    else:
        st.dataframe(summary, use_container_width=True)
        st.caption(
            "Candidates retrieved by VectorRAG; cosine confidence "
            "does not separate right from wrong matches."
        )


# --------------------------------------------------
# 5. HOST GRAPH (ORIGINAL CODE PRESERVED EXACTLY)
# --------------------------------------------------

with graph_tab:

    graph = data.host_graph(frame)

    if graph.number_of_edges() == 0:
        st.write("No suspicious flows to draw.")

    else:
        fig, ax = plt.subplots(figsize=(9, 6))

        pos = nx.spring_layout(graph, seed=7)

        colors = [
            "tab:red" if d["fast_track"] else "tab:orange"
            for _, _, d in graph.edges(data=True)
        ]

        widths = [
            1 + min(d["flows"], 20) / 4
            for _, _, d in graph.edges(data=True)
        ]

        nx.draw_networkx(
            graph,
            pos,
            ax=ax,
            node_size=300,
            font_size=7,
            edge_color=colors,
            width=widths,
            arrows=True,
        )

        ax.axis("off")

        st.pyplot(fig)
        plt.close(fig)

        st.caption(
            "Red = includes FAST_TRACK flows, orange = SLOW_BRAIN only. "
            "Edge width ~ flow count (capped)."
        )


# --------------------------------------------------
# 6. HISTORY
# --------------------------------------------------

with history:
    if incidents.empty:
        st.write("No incidents recorded.")
    else:
        per_day = (
            incidents.dropna(subset=["recorded_at"])
            .set_index("recorded_at")
            .resample("1D")
            .size()
        )

        st.bar_chart(per_day.rename("incidents recorded"))

        st.dataframe(
            incidents[
                [
                    "recorded_at",
                    "incident_id",
                    "kind",
                    "priority",
                    "disposition",
                    "src",
                ]
            ],
            use_container_width=True,
        )