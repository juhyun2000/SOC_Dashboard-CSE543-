import streamlit as st
from elasticsearch import Elasticsearch, helpers
import re
import hashlib
from datetime import datetime, time as dt_time
import pandas as pd
import plotly.graph_objects as go
import os
import joblib
import traceback
import requests
import json
import matplotlib.pyplot as plt
import time

# ------------------------------------------------------------------
# Page config / title
# ------------------------------------------------------------------
st.set_page_config(page_title="Elis Industries - Log Viewer", layout="wide")
st.title("📁 Elis Industries - Log Viewer")

# ------------------------------------------------------------------
# Session state init
# ------------------------------------------------------------------
if "logs_loaded" not in st.session_state:
    st.session_state.logs_loaded = False
if "show_logs" not in st.session_state:
    st.session_state.show_logs = False
if "logs" not in st.session_state:
    st.session_state.logs = []
if "index_name" not in st.session_state:
    st.session_state.index_name = ""
if "start_date" not in st.session_state:
    st.session_state.start_date = datetime.now().date()
if "end_date" not in st.session_state:
    st.session_state.end_date = datetime.now().date()
if "start_time" not in st.session_state:
    st.session_state.start_time = dt_time(0, 0)
if "end_time" not in st.session_state:
    st.session_state.end_time = dt_time(23, 59)

# ------------------------------------------------------------------
# Elasticsearch client
# ------------------------------------------------------------------
es = Elasticsearch("http://es_container:9200")

# ------------------------------------------------------------------
# Parse logs from a local file into docs we can bulk ingest
# ------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def parse_logs(filepath: str):
    """
    Parse log lines like:
    10.19.2025 17:51:49 CRITICAL SomeComponent some message...
    into structured docs usable for Elasticsearch bulk ingest.
    """
    pattern = re.compile(
        r"(\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}) (\w+) (\w+)\s+(.+)"
    )
    logs = []

    with open(filepath, "r") as f:
        for line in f:
            m = pattern.match(line.strip())
            if not m:
                continue

            ts_str, severity, component, message = m.groups()
            try:
                ts_obj = datetime.strptime(ts_str, "%m.%d.%Y %H:%M:%S")

                uid = hashlib.md5(
                    f"{ts_str}_{severity}_{component}_{message}".encode()
                ).hexdigest()

                logs.append(
                    {
                        "_index": "elis_logs",
                        "_id": uid,
                        "_source": {
                            "timestamp": ts_obj.isoformat(),
                            "severity": severity,
                            "component": component,
                            "message": message,
                            "id": uid,
                        },
                    }
                )
            except Exception:
                continue

    index_name = logs[0]["_index"] if logs else None
    return logs, index_name


# ------------------------------------------------------------------
# Sidebar: index summary
# ------------------------------------------------------------------
def show_index_summary():
    try:
        indices = es.cat.indices(format="json")
        total_docs = sum(int(idx["docs.count"]) for idx in indices)

        st.sidebar.markdown("### 📊 Index Summary")
        st.sidebar.write(f"**Total Indices:** {len(indices)}")
        st.sidebar.write(f"**Total Documents:** {total_docs:,}")

        for idx in sorted(indices, key=lambda x: x["index"]):
            st.sidebar.write(f"- `{idx['index']}` → {idx['docs.count']} docs")

    except Exception as e:
        st.sidebar.error(f"Error fetching index summary: {e}")


# ------------------------------------------------------------------
# Danger: delete all indices
# ------------------------------------------------------------------
def delete_all_indices():
    try:
        indices = es.cat.indices(format="json")
        for idx in indices:
            es.indices.delete(index=idx["index"])
        st.success("✅ All indices deleted successfully.")
    except Exception as e:
        st.error(f"Error deleting indices: {e}")


def show_table(df, row_style, use_container_width=True):
    styled_df = df if not row_style else df.style.apply(row_style, axis=1)
    st.dataframe(styled_df, use_container_width=use_container_width)


def highlight_critical(row):
    if str(row["severity"]).upper() == "CRITICAL":
        return ["background-color: #ff6666; color: black"] * len(row)
    return [""] * len(row)


def recent_incident_summary(df):
    if not df.empty and "timestamp" in df.columns and "severity" in df.columns:
        df_plot = df.copy()
        df_plot["timestamp"] = pd.to_datetime(
            df_plot["timestamp"], errors="coerce"
        )
        df_plot = df_plot.dropna(subset=["timestamp"]).sort_values("timestamp")

        df_plot = df_plot[~df_plot["severity"].isin(["INFO", "DEBUG"])]

        if df_plot.empty:
            st.info(
                "Not enough non-INFO/DEBUG data to display recent incident summary."
            )
            return

        time_span = (
            df_plot["timestamp"].max() - df_plot["timestamp"].min()
        ).total_seconds()
        if time_span > 60 * 60 * 24 * 28:
            freq, label = "W", "Week"
        elif time_span > 60 * 60 * 24:
            freq, label = "H", "Hour"
        elif time_span > 60 * 10:
            freq, label = "1min", "Minute"
        else:
            freq, label = "30S", "30-Second Interval"

        df_plot = df_plot.set_index("timestamp")
        counts = (
            df_plot.groupby("severity")
            .resample(freq)
            .size()
            .unstack(level=0)
            .fillna(0)
        ).tail(4)

        severity_order = ["CRITICAL", "ERROR", "WARNING"]
        for sev in severity_order:
            if sev not in counts.columns:
                counts[sev] = 0
        counts = counts[severity_order]

        proportions = counts.div(counts.sum(axis=1), axis=0).fillna(0) * 100

        start_ts = counts.index.min()
        end_ts = counts.index.max()

        if freq == "W":
            title = (
                f"Weekly Severity Composition "
                f"({start_ts.strftime('%b %d')} - {end_ts.strftime('%b %d, %Y')})"
            )
            y_labels = counts.index.strftime("%b %d")
        elif freq == "H":
            title = (
                f"Hourly Severity Composition "
                f"({start_ts.strftime('%b %d, %Y')})"
            )
            y_labels = counts.index.strftime("%H:%M")
        elif freq in ["1min", "30S"]:
            title = (
                f"Recent Severity Composition "
                f"({start_ts.strftime('%b %d, %Y')})"
            )
            y_labels = counts.index.strftime("%H:%M:%S")
        elif freq == "D":
            title = f"Daily Severity Composition ({start_ts.year})"
            y_labels = counts.index.strftime("%b %d")
        else:
            title = "Severity Composition"
            y_labels = counts.index.strftime("%H:%M:%S")

        color_map = {
            "CRITICAL": "#e63946",
            "ERROR": "#f3722c",
            "WARNING": "#f9c74f",
        }

        fig = go.Figure()
        for sev in reversed(severity_order):
            fig.add_trace(
                go.Bar(
                    y=y_labels,
                    x=proportions[sev],
                    name=sev,
                    marker_color=color_map.get(sev, "#cccccc"),
                    customdata=counts[sev],
                    hovertemplate=(
                        f"<b>{sev}</b><br>"
                        + "Time: %{y}<br>"
                        + "Count: %{customdata}<br>"
                        + "Proportion: %{x:.1f}%<extra></extra>"
                    ),
                    orientation="h",
                )
            )

        fig.update_layout(
            barmode="stack",
            title=title,
            xaxis_title="Percentage (%)",
            yaxis_title=label,
            xaxis=dict(range=[0, 100]),
            legend_title="Severity",
            height=300,
            margin=dict(l=50, r=10, t=50, b=40),
        )

        st.subheader(f"{label}-wise Severity Composition")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Not enough data to display recent incident summary chart.")


# ------------------------------------------------------------------
# Render sidebar summary immediately
# ------------------------------------------------------------------
show_index_summary()

# ------------------------------------------------------------------
# Main input: log file path
# ------------------------------------------------------------------
log_path = st.text_input(
    "Enter full path to your log file (e.g., /app/elis_industries_logs.log)"
)

if log_path and os.path.exists(log_path) and not st.session_state.logs_loaded:
    logs, index_name = parse_logs(log_path)
    if logs:
        st.session_state.logs = logs
        st.session_state.index_name = index_name
        st.session_state.logs_loaded = True
        st.success(f"✅ Parsed {len(logs):,} log lines from file.")

# ------------------------------------------------------------------
# Ingest button
# ------------------------------------------------------------------
if st.session_state.logs_loaded and st.button("📥 Ingest Logs into Elasticsearch"):
    if es.ping():
        with st.spinner("Ingesting logs..."):
            helpers.bulk(es, st.session_state.logs, raise_on_error=False)
        st.success(
            f"✅ Ingested {len(st.session_state.logs):,} logs into index "
            f"`{st.session_state.index_name}`."
        )
    else:
        st.error("Failed to connect to Elasticsearch.")

# ------------------------------------------------------------------
# View button
# ------------------------------------------------------------------
if st.session_state.logs_loaded and st.button("🔍 View Logs from Elasticsearch"):
    st.session_state.show_logs = True


def escape_query_string(s: str):
    return re.sub(r'([+\-=&|><!(){}\[\]^"~*?:\\/])', r"\\\1", s)


# ------------------------------------------------------------------
# View + filters
# ------------------------------------------------------------------
if st.session_state.show_logs:
    st.subheader("Filters")
    col1, col2 = st.columns(2)

    with col1:
        start_date = st.date_input("Start Date", key="start_date")
        start_time = st.time_input("Start Time", key="start_time")

    with col2:
        end_date = st.date_input("End Date", key="end_date")
        end_time = st.time_input("End Time", key="end_time")

    keyword_filter = st.text_input(
        "Keyword Filter (searches message, severity, component, id; leave blank to disable)"
    )
    show_recent = st.checkbox("Show recent incident summary of logs")

    start_ts = datetime.combine(start_date, start_time)
    end_ts = datetime.combine(end_date, end_time)

    start_iso = start_ts.isoformat(timespec="seconds")
    end_iso = end_ts.isoformat(timespec="seconds")

    es_query = {
        "bool": {
            "filter": [
                {"range": {"timestamp": {"gte": start_iso, "lte": end_iso}}}
            ]
        }
    }

    if keyword_filter.strip():
        es_query["bool"].setdefault("must", []).append(
            {
                "multi_match": {
                    "query": keyword_filter.strip(),
                    "fields": ["message^2", "severity", "component", "id"],
                    "type": "best_fields",
                    "operator": "and",
                }
            }
        )

    try:
        result = es.search(
            index=st.session_state.index_name,
            size=10_000,
            sort=[{"timestamp": {"order": "asc"}}],
            query=es_query,
        )

        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            st.warning("No logs found in the given time range (and keyword, if any).")
        else:
            rows = []
            for h in hits:
                src = h.get("_source", {})
                rows.append(
                    {
                        "timestamp": src.get("timestamp"),
                        "severity": src.get("severity"),
                        "component": src.get("component"),
                        "message": src.get("message"),
                        "_id": h.get("_id"),
                    }
                )

            df = pd.DataFrame(rows)
            st.session_state["filtered_df"] = df

            st.subheader("Logs")
            st.write(f"Showing {len(df):,} logs:")
            show_table(df, highlight_critical, use_container_width=True)

            if show_recent:
                recent_incident_summary(df)

            # severity summary + compact chart
            if df.empty or "severity" not in df.columns:
                st.info("No data available for severity chart with current filters.")
            else:
                try:
                    severity_counts = (
                        df["severity"]
                        .value_counts()
                        .rename_axis("severity")
                        .reset_index(name="count")
                    )

                    if (
                        "severity" not in severity_counts.columns
                        or "count" not in severity_counts.columns
                    ):
                        st.info(
                            "No valid severity data to chart for this filter."
                        )
                    else:
                        order = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]
                        severity_counts["severity"] = pd.Categorical(
                            severity_counts["severity"],
                            categories=order,
                            ordered=True,
                        )
                        severity_counts = (
                            severity_counts.sort_values("severity").dropna()
                        )

                        if not severity_counts.empty:
                            sum_col, chart_col = st.columns([1, 1])

                            with sum_col:
                                st.subheader("Severity Summary")
                                st.dataframe(
                                    severity_counts, use_container_width=True
                                )

                            with chart_col:
                                st.subheader("Severity Distribution Chart")

                                x = severity_counts["severity"].astype(str).tolist()
                                y = severity_counts["count"].tolist()

                                color_map = {
                                    "CRITICAL": "#ff4d4d",
                                    "ERROR": "#ff9933",
                                    "WARNING": "#ffcc00",
                                    "INFO": "#4da6ff",
                                    "DEBUG": "#999999",
                                }
                                colors = [
                                    color_map.get(level, "#cccccc") for level in x
                                ]

                                fig, ax = plt.subplots(figsize=(5, 2.5))
                                ax.bar(x, y, color=colors)

                                ax.set_title("Log Count by Severity", fontsize=6)
                                ax.set_xlabel("Severity Level", fontsize=4)
                                ax.set_ylabel("Count", fontsize=4)
                                ax.set_ylim(0, max(y) * 1.15)
                                ax.tick_params(axis="x", labelsize=4)
                                ax.tick_params(axis="y", labelsize=4)

                                for i, v in enumerate(y):
                                    ax.text(
                                        i,
                                        v,
                                        str(v),
                                        ha="center",
                                        va="bottom",
                                        fontsize=4,
                                    )

                                chart_col.pyplot(fig)
                        else:
                            st.info("No severity data to chart for this filter.")

                except Exception as chart_err:
                    st.error(f"Failed to build summary / chart: {chart_err}")

            # download filtered logs
            csv_filtered = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="⬇️ Download filtered logs as CSV",
                data=csv_filtered,
                file_name="elis_filtered_logs.csv",
                mime="text/csv",
            )

    except Exception as e:
        st.error(f"Failed to query logs: {e}")

# ------------------------------------------------------------------
# Delete All Indices "danger zone"
# ------------------------------------------------------------------
with st.expander("🗑️ Delete All Indices", expanded=False):
    st.warning("⚠️ This will permanently delete all indices and logs.")
    confirm = st.checkbox("I understand the risks and want to proceed.")
    if confirm:
        if st.button("❌ Delete All Indices"):
            delete_all_indices()

# -----------------------------------------------------
# Tag ONLY the Filtered Logs with ML Predictions
# -----------------------------------------------------
try:
    attack_model = joblib.load("eval_model_attack_type.pkl")
    priority_model = joblib.load("eval_model_priority.pkl")
    models_loaded = True
except Exception as e:
    st.error(f"Failed to load ML models: {e}")
    models_loaded = False

if models_loaded and st.session_state.get("show_logs", False):
    with st.expander("Tag Logs with ML Predictions"):
        st.markdown(
            """
        This will tag only the logs currently visible in the filtered table.
        with `attack_type` and `priority`.
        """
        )

        if st.button("Tag These Logs Only"):
            try:
                if "filtered_df" not in st.session_state:
                    st.error(
                        "No filtered logs found. First run 'View Logs from Elasticsearch'."
                    )
                    st.stop()

                df_filtered = st.session_state["filtered_df"]

                if df_filtered.empty:
                    st.warning("No logs available to tag.")
                    st.stop()

                messages = df_filtered["message"].tolist()
                ids = df_filtered["_id"].tolist()

                attack_preds = attack_model.predict(messages)
                priority_preds = priority_model.predict(messages)

                updates = []
                for _id, attack, priority in zip(
                    ids, attack_preds, priority_preds
                ):
                    updates.append(
                        {
                            "_op_type": "update",
                            "_index": "elis_logs",
                            "_id": _id,
                            "doc": {
                                "attack_type": attack,
                                "priority": priority,
                            },
                        }
                    )

                helpers.bulk(es, updates, raise_on_error=False)

                df_filtered["attack_type"] = attack_preds
                df_filtered["priority"] = priority_preds
                st.session_state["tagged_df"] = df_filtered
                st.session_state["tagged"] = True

                st.success(f"Tagged {len(df_filtered):,} filtered logs successfully!")
            except Exception as e:
                st.error(f"Tagging failed: {e}")

# -----------------------------------------------------
# View Tagged Filtered Logs (ML output) + download
# -----------------------------------------------------
if st.session_state.get("tagged", False):
    with st.expander("View Tagged Logs"):
        if st.button("Show Tagged Filtered Logs"):
            try:
                df_tagged = st.session_state.get("tagged_df")

                if df_tagged is None or df_tagged.empty:
                    st.warning("No tagged logs found.")
                else:
                    st.subheader("Logs with ML-based Tags (Attack Type & Priority)")
                    view_cols = [
                        "timestamp",
                        "severity",
                        "component",
                        "message",
                        "attack_type",
                        "priority",
                    ]
                    st.dataframe(df_tagged[view_cols], use_container_width=True)

                    csv_ml = df_tagged[view_cols].to_csv(
                        index=False
                    ).encode("utf-8")
                    st.download_button(
                        label="⬇️ Download ML-tagged logs as CSV",
                        data=csv_ml,
                        file_name="elis_ml_tagged_logs.csv",
                        mime="text/csv",
                    )
            except Exception as e:
                st.error(f"Failed to display tagged logs: {e}")

# -----------------------------------------------------
# LLM via Gemma3:1b — One-by-One Inference (with Attack Vector)
# -----------------------------------------------------
if st.session_state.get("tagged", False):
    with st.expander("AI based recommendations"):
        st.markdown(
            """
            This might take a minute!
            """
        )

        if st.button("Confirm"):
            try:
                df_tagged = st.session_state.get("tagged_df")
                if df_tagged is None or df_tagged.empty:
                    st.warning("No tagged logs available.")
                    st.stop()

                for col in [
                    "nist_phase",
                    "mitre_attack_mapping",
                    "attack_vector",
                    "recommended_action",
                ]:
                    if col not in df_tagged.columns:
                        df_tagged[col] = ""

                priority_norm = (
                    df_tagged["priority"].fillna("").str.strip().str.lower()
                )
                df_all_high = df_tagged[priority_norm == "high"].copy()

                total_high = len(df_all_high)
                df_high = df_all_high.head(100)

                if total_high == 0:
                    st.info("No high-priority logs found.")
                    st.stop()

                st.write(f"Total High-priority logs: **{total_high}**")
                st.write(f"Now processing: **{len(df_high)}** logs using Gemma3…")

                start_time = time.time()

                updates = []
                success_count = 0
                raw_responses = []

                MITRE_TACTICS = [
                    "TA0043 Reconnaissance",
                    "TA0042 Resource Development",
                    "TA0001 Initial Access",
                    "TA0002 Execution",
                    "TA0003 Persistence",
                    "TA0004 Privilege Escalation",
                    "TA0005 Defense Evasion",
                    "TA0006 Credential Access",
                    "TA0007 Discovery",
                    "TA0008 Lateral Movement",
                    "TA0009 Collection",
                    "TA0011 Command and Control",
                    "TA0010 Exfiltration",
                    "TA0040 Impact",
                ]

                NIST_ATTACK_VECTORS = [
                    "External/Removable Media",
                    "Attrition",
                    "Web",
                    "Email",
                    "Impersonation",
                    "Improper Usage",
                    "Loss or Theft of Equipment",
                    "Other",
                ]

                def build_prompt(row):
                    return f"""
You are a security analyst. Analyze the log entry below.

Log Message: "{row['message']}"
Severity: {row['severity']}
Component: {row['component']}
Attack Type: {row['attack_type']}
Priority: {row['priority']}

Return JSON with:
- "nist_phase": one of ["Govern","Identify","Protect","Detect","Respond","Recover"]
- "mitre_attack_mapping": one valid MITRE tactic from: {MITRE_TACTICS}
- "attack_vector": one of {NIST_ATTACK_VECTORS}
- "recommended_action": one practical sentence

Only return JSON. No commentary.
"""

                def clean_json(raw):
                    return raw.replace("```json", "").replace("```", "").strip()

                def to_scalar_str(x):
                    if x is None:
                        return ""
                    if isinstance(x, (list, tuple, set)):
                        return ", ".join(str(v) for v in x)
                    if isinstance(x, dict):
                        return json.dumps(x, ensure_ascii=False)
                    return str(x)

                for idx, (i, row) in enumerate(df_high.iterrows()):
                    prompt = build_prompt(row)

                    try:
                        response = requests.post(
                            "http://host.docker.internal:11434/api/generate",
                            json={
                                "model": "gemma3:1b",
                                "prompt": prompt,
                                "stream": False,
                            },
                            timeout=60,
                        ).json()
                        raw = response.get("response", "").strip()
                        raw_responses.append((idx + 1, raw))
                    except Exception as e:
                        raw_responses.append((idx + 1, f"ERROR: {e}"))
                        raw = ""

                    cleaned = clean_json(raw)

                    nist = mitre = reco = vector = ""
                    try:
                        parsed = json.loads(cleaned)
                        nist = to_scalar_str(parsed.get("nist_phase", ""))
                        mitre = to_scalar_str(parsed.get("mitre_attack_mapping", ""))
                        reco = to_scalar_str(parsed.get("recommended_action", ""))
                        vector = to_scalar_str(parsed.get("attack_vector", ""))
                        success_count += 1
                    except Exception:
                        pass

                    df_tagged.loc[i, "nist_phase"] = nist
                    df_tagged.loc[i, "mitre_attack_mapping"] = mitre
                    df_tagged.loc[i, "recommended_action"] = reco
                    df_tagged.loc[i, "attack_vector"] = vector

                    updates.append(
                        {
                            "_op_type": "update",
                            "_index": "elis_logs",
                            "_id": row["_id"],
                            "doc": {
                                "nist_phase": nist,
                                "mitre_attack_mapping": mitre,
                                "attack_vector": vector,
                                "recommended_action": reco,
                            },
                        }
                    )

                helpers.bulk(es, updates, raise_on_error=False)
                st.session_state["tagged_df"] = df_tagged
                st.session_state["gemma_raw_outputs"] = raw_responses

                duration = time.time() - start_time

                st.success(
                    f"✨ Parsed {success_count}/{len(df_high)} logs successfully!"
                )
                st.info(f"⏱️ Processing time: **{duration:.2f} seconds**")
            except Exception as e:
                st.error(f"LLM processing failed: {e}")
                st.code(traceback.format_exc())

# -----------------------------------------------------
# View LLM-Tagged Logs (Only Fully Tagged) + download
# -----------------------------------------------------
if st.session_state.get("tagged", False):
    with st.expander("View Recommendations"):
        if st.button("Show LLM Tagged Logs"):
            try:
                df_tagged = st.session_state.get("tagged_df")

                df_llm = df_tagged[
                    df_tagged["nist_phase"].astype(bool)
                    & df_tagged["mitre_attack_mapping"].astype(bool)
                    & df_tagged["attack_vector"].astype(bool)
                    & df_tagged["recommended_action"].astype(bool)
                ]

                if df_llm.empty:
                    st.info("No logs have complete LLM tags yet.")
                else:
                    st.subheader(f"{len(df_llm)} Logs Annotated by LLM")

                    view_cols = [
                        "timestamp",
                        "severity",
                        "component",
                        "message",
                        "attack_type",
                        "priority",
                        "nist_phase",
                        "mitre_attack_mapping",
                        "attack_vector",
                        "recommended_action",
                    ]

                    st.dataframe(df_llm[view_cols], use_container_width=True)

                    csv_llm = df_llm[view_cols].to_csv(index=False).encode("utf-8")

                    st.download_button(
                        label="⬇️ Download LLM-annotated logs as CSV",
                        data=csv_llm,
                        file_name="elis_llm_incident_report.csv",
                        mime="text/csv",
                    )
            except Exception as e:
                st.error(f"Failed to display LLM-tagged logs: {e}")
