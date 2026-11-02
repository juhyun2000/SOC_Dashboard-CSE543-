import streamlit as st
from elasticsearch import Elasticsearch, helpers
import os
import re
import hashlib
from datetime import datetime

st.set_page_config(page_title="Log Viewer", layout="wide")
st.title("Log Viewer")

# Connect to Elasticsearch
es = Elasticsearch("http://elasticsearch:9200")

# ------------------ Function: Parse Logs ------------------
def parse_logs(filepath):
    log_pattern = re.compile(r"(\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}) (\w+)\s+(.+)")
    logs = []

    with open(filepath, 'r') as f:
        lines = f.readlines()

    for line in lines:
        match = log_pattern.match(line.strip())
        if match:
            ts_str, severity, message = match.groups()
            try:
                ts_obj = datetime.strptime(ts_str, '%m.%d.%Y %H:%M:%S')
                # Using unique ID using hash of log content
                uid = hashlib.md5(f"{ts_str}_{severity}_{message}".encode()).hexdigest()

                logs.append({
                    "_index": f"{ts_obj.strftime('%Y%m%d')}_logs",
                    "_id": uid,
                    "_source": {
                        "timestamp": ts_obj.isoformat(),
                        "severity": severity,
                        "message": message
                    }
                })
            except ValueError:
                continue

    index_name = logs[0]['_index'] if logs else None
    return logs, index_name

# ------------------ Function: Index Summary ------------------
def show_index_summary():
    try:
        indices = es.cat.indices(format="json")
        st.sidebar.markdown("### 📊 Index Summary")
        st.sidebar.write(f"**Total Indices:** {len(indices)}")
        for idx in indices:
            st.sidebar.write(f"- `{idx['index']}` → {idx['docs.count']} docs")
    except Exception as e:
        st.sidebar.error(f"Failed to fetch indices: {e}")

# ------------------ Function: Delete All Indices ------------------
def delete_all_indices():
    try:
        indices = es.cat.indices(format="json")
        for idx in indices:
            es.indices.delete(index=idx["index"])
        st.success("All indices deleted successfully.")
    except Exception as e:
        st.error(f"Error deleting indices: {e}")

# ------------------ Main UI ------------------
# Always showing summary in sidebar
show_index_summary()

log_path = st.text_input("Enter full path to your log file (e.g., /app/generated_logs.log)")

if log_path and os.path.exists(log_path):
    logs, index_name = parse_logs(log_path)

    if logs:
        st.success(f"Parsed {len(logs):,} log lines from file.")

        # Ingest Button
        if st.button("Ingest Logs into Elasticsearch"):
            if es.ping():
                with st.spinner("Ingesting logs..."):
                    helpers.bulk(es, logs)
                st.success(f"Inserted {len(logs):,} logs into index `{index_name}`.")
            else:
                st.error("Failed to connect to Elasticsearch.")

        # View Button
        if st.button("View Logs from Elasticsearch"):
            st.subheader(f"Displaying first 10,000 logs from index `{index_name}`")
            try:
                result = es.search(
                    index=index_name,
                    size=10_000,
                    sort="timestamp:asc",
                    query={"match_all": {}}
                )
                hits = result['hits']['hits']
                if hits:
                    st.dataframe([
                        {
                            "timestamp": h['_source']['timestamp'],
                            "severity": h['_source']['severity'],
                            "message": h['_source']['message']
                        } for h in hits
                    ])
                else:
                    st.warning("No logs found in index.")
            except Exception as e:
                st.error(f"Failed to query logs: {e}")
    else:
        st.error("No valid log lines found in the file.")
elif log_path:
    st.error("Invalid file path. Please check and try again.")

# Delete All Indices Button
with st.expander("🗑️ Delete All Indices", expanded=False):
    st.warning("This will delete ALL indices and cannot be undone.")
    confirm = st.checkbox("I understand the risks and want to delete all indices")
    if confirm:
        if st.button("Delete Now"):
            delete_all_indices()