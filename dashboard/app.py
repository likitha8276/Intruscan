"""INTRUSCAN SOC dashboard (Streamlit)."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
import subprocess
import tempfile

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


st.set_page_config(page_title="INTRUSCAN SOC", layout="wide")
st.title("INTRUSCAN - SOC dashboard")


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:
    st.header("Data sources")

    scored_path = st.text_input(
        "Scored flows (JSONL)",
        os.environ.get("INTRUSCAN_SCORED", "scored_flows.jsonl"),
    )

    db_path = st.text_input(
        "Incident store (SQLite)",
        os.environ.get("INTRUSCAN_INCIDENT_DB", "incidents.db"),
    )

    max_rows = st.number_input(
        "Max flow rows to load",
        1_000,
        1_000_000,
        200_000,
        step=10_000,
    )

    st.caption("Refresh the page (or press R) to re-read the files.")


# --------------------------------------------------
# DATASET UPLOAD AND PIPELINE
# --------------------------------------------------

CICIDS_MODEL = ROOT / "data" / "models" / "fast_brain_cicids2017.joblib"
UGR16_MODEL = ROOT / "data" / "models" / "fast_brain_ugr16_v3.joblib"
UGR16_BASELINE = ROOT / "data" / "raw" / "ugr16_train.jsonl"

st.subheader("Upload dataset and run analysis")

dataset = st.radio(
    "Dataset type",
    ["CICIDS2017", "UGR'16"],
    horizontal=True,
)
is_ugr = dataset == "UGR'16"

if is_ugr:
    st.caption(
        "UGR'16: upload an official headerless 13-column labelled CSV (a small "
        "sample, not a whole weekly file). It is converted with "
        "tools/parse_ugr16_native.py and scored with fast_brain_ugr16_v3. "
        "Routing uses the approved v3 thresholds from soc_agent/thresholds.json "
        "(lower 0.596, upper 0.635), bound to the v3 model."
    )
else:
    st.caption(
        "CICIDS2017: uses tools/parse_cicids2017.py and "
        "fast_brain_cicids2017.joblib."
    )

uploaded_file = st.file_uploader(
    f"Upload {dataset} CSV",
    type=["csv"],
    help=(
        "Headerless official UGR'16 CSV (13 columns)."
        if is_ugr
        else "Upload a CICIDS2017 flow CSV file."
    ),
)

max_events = 12
if is_ugr:
    max_events = st.number_input(
        "Max LLM events (one LLM call per source; rate limits apply)",
        min_value=1,
        max_value=100,
        value=12,
        step=1,
    )

confirm_write = st.checkbox(
    "I understand this run writes to the sidebar paths "
    f"(`{scored_path}` and `{db_path}`) and may replace or extend them."
)

if st.button(
    "Run Intruscan analysis",
    type="primary",
    disabled=uploaded_file is None or not confirm_write,
):
    model_path = UGR16_MODEL if is_ugr else CICIDS_MODEL
    scored_output = Path(scored_path)
    incident_db = Path(db_path)
    rag_output = (
        ROOT / "smoke" / "ugr16_upload_alerts.jsonl"
        if is_ugr
        else ROOT / "rag_soc_alerts.jsonl"
    )

    if not model_path.is_file():
        st.error(f"Trained model not found: {model_path}")

    elif is_ugr and not UGR16_BASELINE.is_file():
        st.error(f"UGR'16 baseline file not found: {UGR16_BASELINE}")

    else:
        scored_output.parent.mkdir(parents=True, exist_ok=True)
        incident_db.parent.mkdir(parents=True, exist_ok=True)
        rag_output.parent.mkdir(parents=True, exist_ok=True)

        def run_step(label, command):
            st.write(f"**{label}**")

            result = subprocess.run(
                command,
                cwd=ROOT,
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

                    # STEP 1: CSV PARSING
                    if is_ugr:
                        source_name = re.sub(
                            r"[^A-Za-z0-9_.-]+",
                            "_",
                            Path(uploaded_file.name).stem,
                        ) or "ugr16_upload"
                        parse_command = [
                            sys.executable,
                            "tools/parse_ugr16_native.py",
                            str(csv_path),
                            str(parsed_path),
                            "--source-name",
                            source_name,
                        ]
                    else:
                        parse_command = [
                            sys.executable,
                            "tools/parse_cicids2017.py",
                            str(csv_path),
                            str(parsed_path),
                        ]

                    run_step("Step 1: Parsing CSV", parse_command)

                    # STEP 2: FAST BRAIN
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
                            str(model_path),
                            "--output",
                            str(scored_output),
                        ],
                    )

                    # STEP 3: RAG AND AGENTIC SLOW BRAIN
                    handoff_command = [
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
                        str(model_path),
                        "--llm",
                        "auto",
                        "--model",
                        "openai/gpt-oss-20b",
                    ]

                    if is_ugr:
                        handoff_command += [
                            "--chroma-path",
                            str(ROOT / "smoke" / "chroma_pipe"),
                            "--mitre",
                            "seed",
                            "--baseline-file",
                            str(UGR16_BASELINE),
                            "--baseline-label",
                            "background",
                            "--max-events",
                            str(int(max_events)),
                            "--timeout",
                            "600",
                        ]

                    run_step(
                        "Step 3: RAG / Slow Brain handoff",
                        handoff_command,
                    )

            st.success("Dataset processed successfully!")
            st.cache_data.clear()
            st.rerun()

        except Exception as exc:
            st.error(f"Analysis failed: {exc}")


# --------------------------------------------------
# LOAD DATA
# --------------------------------------------------


def _flows(path: str, rows: int, mtime: float):
    return data.load_scored_flows(path, rows)



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
        st.warning(
            f"{loaded.invalid_rows} unreadable rows were skipped."
        )

    if loaded.truncated:
        st.warning(
            f"Only the most recent {int(max_rows):,} rows are loaded."
        )

    if not frame.empty:

        left, right = st.columns(2)

        left.subheader("Benign vs suspicious (model routing)")
        left.bar_chart(pd.Series(data.traffic_split(frame)))

        left.caption(
            "Suspicious = routed to SLOW_BRAIN or FAST_TRACK. "
            "Not a confirmed attack."
        )

        right.subheader("Routing decisions")
        right.bar_chart(pd.Series(counts))

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
            st.dataframe(crosstab)

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
        kinds = st.multiselect(
            "Kind",
            sorted(incidents["kind"].unique()),
            default=sorted(incidents["kind"].unique()),
        )

        prios = st.multiselect(
            "Priority",
            sorted(incidents["priority"].unique()),
            default=sorted(incidents["priority"].unique()),
        )

        view = incidents[
            incidents["kind"].isin(kinds)
            & incidents["priority"].isin(prios)
        ]

        st.dataframe(
            view[
                [
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
            ],
            use_container_width=True,
        )


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

        if record:

            a, b, c = st.columns(3)

            a.metric("Priority", record["priority"])
            b.metric("Disposition", record["disposition"])
            c.metric(
                "LLM called",
                "yes" if record["llm_called"] else "no",
            )

            st.write(
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
                }
            )

            st.subheader("Reasons")
            st.write(record["reasons"])

            # AGENTIC AI RESULTS
            soc = record.get("soc_result") or {}

            if soc:

                st.divider()
                st.subheader("Agentic AI Investigation")

                st.success(
                    "SOC Agent investigation result available"
                )

                # AGENT DECISION
                a, b, c = st.columns(3)

                a.metric(
                    "Agent outcome",
                    soc.get("outcome", "Unknown"),
                )

                b.metric(
                    "LLM execution",
                    f"{soc.get('llm_ms', 0):.1f} ms",
                )

                c.metric(
                    "Verification",
                    f"{soc.get('verify_ms', 0):.2f} ms",
                )

                # REASONING
                st.markdown("#### 1. Agent decision and reasoning")

                st.write(
                    soc.get(
                        "reasons",
                        ["No reasons returned"],
                    )
                )

                # PROPOSED ACTION
                st.markdown("#### 2. Proposed action")

                action = soc.get("action")

                if action:
                    st.json(action)
                else:
                    st.info("No action proposed by the agent.")

                # VERIFICATION
                st.markdown("#### 3. Evidence verification")

                verdicts = soc.get("verdicts", [])

                if verdicts:
                    for verdict in verdicts:
                        st.write(f"• {verdict}")
                else:
                    st.info(
                        "No verification verdicts returned."
                    )

                # RISK GATE
                st.markdown("#### 4. Risk gate")

                flags = soc.get("gate_flags", [])

                if flags:
                    for flag in flags:
                        st.warning(flag)
                else:
                    st.success(
                        "No risk-gate flags returned."
                    )

                # COMPLETE RESPONSE
                with st.expander(
                    "View complete SOC agent response"
                ):
                    st.json(soc)

            else:
                st.info(
                    "No SOC agent result is stored for this incident."
                )

            # EVIDENCE
            st.divider()
            st.subheader("Evidence")

            evidence = record["evidence"]

            if evidence.get("logs"):
                for event_id, text in evidence["logs"].items():
                    st.code(f"[{event_id}]\n{text}")

            if evidence.get("events"):
                st.dataframe(
                    pd.DataFrame(evidence["events"]),
                    use_container_width=True,
                )

            if evidence.get("flows"):
                st.dataframe(
                    pd.DataFrame(evidence["flows"]),
                    use_container_width=True,
                )

            # MITRE DETAILS
            if record["mitre"]:
                st.subheader("ATT&CK candidates (similarity-ranked, not verdicts)")

                st.dataframe(
                    pd.DataFrame(record["mitre"]),
                    use_container_width=True,
                )

            if record["kind"] == "fast_track":
                st.info(
                    "FAST_TRACK: recorded as HIGH priority without "
                    "an LLM call. No ATT&CK lookup was performed."
                )


# --------------------------------------------------
# 4. MITRE ATT&CK
# --------------------------------------------------

with mitre_tab:

    summary = data.mitre_summary(
        store.list() if store else []
    )

    if summary.empty:
        st.write(
            "No ATT&CK candidates recorded "
            "(they come from the RAG handoff)."
        )

    else:
        st.dataframe(
            summary,
            use_container_width=True,
        )

        st.caption(
            "Candidates retrieved by VectorRAG; cosine confidence "
            "does not separate right from wrong matches."
        )


# --------------------------------------------------
# 5. HOST GRAPH
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

        st.bar_chart(
            per_day.rename("incidents recorded")
        )

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
            width="stretch",
        )