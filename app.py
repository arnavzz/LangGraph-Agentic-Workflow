import streamlit as st
import pandas as pd
from streamlit_autorefresh import st_autorefresh
import json
import sqlite3

# Sample function to fetch task statuses (Replace with real backend logic)
def get_task_status():
    return [
        {"Task": "Nmap Scan", "Status": "Completed", "Logs": "Nmap scan detected 3 open ports."},
        {"Task": "Gobuster Directory Enumeration", "Status": "Running", "Logs": "Enumerating directories..."},
        {"Task": "SQL Injection Scan", "Status": "Pending", "Logs": "Waiting to start..."},
        {"Task": "Subdomain Discovery", "Status": "Failed", "Logs": "No subdomains found. Possible rate limit."},
    ]

# Sample function to fetch final audit report
def get_audit_report():
    return {
        "Total Tasks": 4,
        "Completed": 1,
        "Running": 1,
        "Pending": 1,
        "Failed": 1,
        "Scope Violations": ["Potential unrestricted directory access"],
        "Vulnerabilities Found": ["Open Ports (22, 80, 443)", "Potential SQL Injection"]
    }

# Streamlit UI
st.set_page_config(page_title="Cybersecurity Pipeline Dashboard", layout="wide")
st.title("🔍 Cybersecurity Agent Dashboard")

# Task Status Section
st.subheader("📌 Task Execution Status")
task_data = get_task_status()
df = pd.DataFrame(task_data)
st.dataframe(df, use_container_width=True)

# Logs Section
st.subheader("📜 Task Logs")
for task in task_data:
    with st.expander(f"🔹 {task['Task']} - {task['Status']}"):
        st.text(task["Logs"])

# Final Report Section
st.subheader("📑 Final Audit Report")
audit_report = get_audit_report()
st.json(audit_report)

# Dashboard Metrics
st.subheader("📊 Task Overview")
col1, col2, col3, col4 = st.columns(4)
col1.metric("✅ Completed", audit_report["Completed"])
col2.metric("⏳ Running", audit_report["Running"])
col3.metric("🕒 Pending", audit_report["Pending"])
col4.metric("❌ Failed", audit_report["Failed"])

st.warning(f"⚠ Scope Violations: {', '.join(audit_report['Scope Violations'])}")
st.error(f"🛑 Vulnerabilities Found: {', '.join(audit_report['Vulnerabilities Found'])}")

# Auto-refresh every 10 seconds
count= st_autorefresh(interval=10 * 1000, key="refresh")
st.title("Real-Time Task Monitoring")
st.write(f"Page refreshed {count} times.")