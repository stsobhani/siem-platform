"""
SOC Analyst Dashboard (Streamlit)

Run:
    streamlit run siem/dashboard/app.py

Shows:
    - KPI header (open alerts, critical count, events ingested, avg risk score)
    - Alerts table with filters
    - Attack trend over time
    - Top attacking IPs
    - Severity breakdown
    - User behavior analytics (risk per user, login-hour heatmap)
    - ML anomaly detection results
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pandas as pd
import plotly.express as px
import streamlit as st
from sqlalchemy import text

from siem.config import config
from siem.db.session import get_engine

st.set_page_config(page_title="SIEM Dashboard", layout="wide")

engine = get_engine()


@st.cache_data(ttl=30)
def load_alerts() -> pd.DataFrame:
    df = pd.read_sql(text("SELECT * FROM alerts ORDER BY detected_at DESC"), engine)
    if not df.empty:
        df["detected_at"] = pd.to_datetime(df["detected_at"])
    return df


@st.cache_data(ttl=30)
def load_events() -> pd.DataFrame:
    df = pd.read_sql(text("SELECT * FROM normalized_events ORDER BY event_time"), engine)
    if not df.empty:
        df["event_time"] = pd.to_datetime(df["event_time"])
    return df


@st.cache_data(ttl=30)
def load_ml_scores() -> pd.DataFrame:
    df = pd.read_sql(text("SELECT * FROM ml_anomaly_scores ORDER BY event_time"), engine)
    if not df.empty:
        df["event_time"] = pd.to_datetime(df["event_time"])
    return df


alerts_df = load_alerts()
events_df = load_events()
ml_df = load_ml_scores()

# ---------------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------------
st.sidebar.title("SIEM Platform")

severity_filter = st.sidebar.multiselect(
    "Severity", options=["low", "medium", "high", "critical"],
    default=["low", "medium", "high", "critical"],
)
rule_filter = st.sidebar.multiselect(
    "Rule", options=sorted(alerts_df["rule_name"].unique()) if not alerts_df.empty else [],
    default=sorted(alerts_df["rule_name"].unique()) if not alerts_df.empty else [],
)

if st.sidebar.button("Refresh data"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown(
    "**Log Sources:** Windows authentication, Linux SSH, firewall, and web server events.\n\n"
    "**Detection Engine:** Rule-based threat detection with ML-powered anomaly scoring using Isolation Forest.\n\n"
    "**Capabilities:** Real-time event ingestion, alert generation, threat intelligence matching, and security monitoring.\n\n"
    "**Technology Stack:** Python, PostgreSQL, pandas, scikit-learn, Streamlit, Splunk HEC."
)



filtered_alerts = alerts_df[
    alerts_df["severity"].isin(severity_filter) & alerts_df["rule_name"].isin(rule_filter)
] if not alerts_df.empty else alerts_df

# ---------------------------------------------------------------------------
# KPI header
# ---------------------------------------------------------------------------
st.title("Security Operations Center Dashboard")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Events Ingested", f"{len(events_df):,}")
col2.metric("Open Alerts", f"{(alerts_df['status'] == 'open').sum() if not alerts_df.empty else 0:,}")
col3.metric("Critical Alerts", f"{(alerts_df['severity'] == 'critical').sum() if not alerts_df.empty else 0:,}")
avg_risk = alerts_df["risk_score"].astype(float).mean() if not alerts_df.empty else 0
col4.metric("Avg Risk Score", f"{avg_risk:.1f}")
col5.metric("ML Anomalies Flagged", f"{int(ml_df['is_anomaly'].sum()) if not ml_df.empty else 0:,}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Row 1: Attack trend + severity breakdown
# ---------------------------------------------------------------------------
c1, c2 = st.columns([2, 1])

with c1:
    st.subheader("Alert Trend Over Time")
    if not filtered_alerts.empty:
        trend = (
            filtered_alerts.set_index("detected_at")
            .resample("1h")["id"].count()
            .reset_index(name="alert_count")
        )
        fig = px.area(trend, x="detected_at", y="alert_count",
                       labels={"detected_at": "Time", "alert_count": "Alerts"})
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alerts match the current filters.")

with c2:
    st.subheader("Severity Breakdown")
    if not filtered_alerts.empty:
        sev_counts = filtered_alerts["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        color_map = {"low": "#4CAF50", "medium": "#FFC107", "high": "#FF5722", "critical": "#B71C1C"}
        fig = px.pie(sev_counts, names="severity", values="count",
                     color="severity", color_discrete_map=color_map, hole=0.45)
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data.")

# ---------------------------------------------------------------------------
# Row 2: Top attacking IPs + rule breakdown
# ---------------------------------------------------------------------------
c3, c4 = st.columns(2)

with c3:
    st.subheader("Top Attacking IP Addresses")
    if not filtered_alerts.empty and filtered_alerts["src_ip"].notna().any():
        top_ips = (
            filtered_alerts.dropna(subset=["src_ip"])
            .groupby("src_ip")
            .agg(alerts=("id", "count"), max_risk=("risk_score", "max"))
            .sort_values("alerts", ascending=False)
            .head(10)
            .reset_index()
        )
        fig = px.bar(top_ips, x="alerts", y="src_ip", orientation="h",
                     color="max_risk", color_continuous_scale="Reds",
                     labels={"src_ip": "Source IP", "alerts": "Alert Count", "max_risk": "Max Risk"})
        fig.update_layout(height=350, margin=dict(l=10, r=10, t=10, b=10), yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No IP-based alerts to show.")

with c4:
    st.subheader("Alerts by Detection Rule")
    if not filtered_alerts.empty:
        rule_counts = filtered_alerts["rule_name"].value_counts().reset_index()
        rule_counts.columns = ["rule_name", "count"]
        fig = px.bar(rule_counts, x="count", y="rule_name", orientation="h",
                     labels={"rule_name": "Rule", "count": "Alert Count"})
        fig.update_layout(height=350, margin=dict(l=10, r=10, t=10, b=10), yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data.")

# ---------------------------------------------------------------------------
# Row 3: User behavior analytics
# ---------------------------------------------------------------------------
st.subheader("User Behavior Analytics")
c5, c6 = st.columns(2)

with c5:
    st.markdown("**Risk score by user** (sum of alert risk scores)")
    if not filtered_alerts.empty and filtered_alerts["username"].notna().any():
        user_risk = (
            filtered_alerts.dropna(subset=["username"])
            .groupby("username")["risk_score"].sum()
            .sort_values(ascending=False)
            .reset_index()
        )
        fig = px.bar(user_risk, x="username", y="risk_score",
                     labels={"username": "User", "risk_score": "Cumulative Risk"})
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No user-attributed alerts.")

with c6:
    st.markdown("**Login activity heatmap** (hour of day versus day)")
    logins = events_df[events_df["event_type"] == "login_success"].copy() if not events_df.empty else pd.DataFrame()
    if not logins.empty:
        logins["hour"] = logins["event_time"].dt.hour
        logins["date"] = logins["event_time"].dt.date.astype(str)
        heat = logins.groupby(["date", "hour"]).size().reset_index(name="logins")
        fig = px.density_heatmap(heat, x="hour", y="date", z="logins",
                                  color_continuous_scale="Blues", nbinsx=24)
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No login events yet.")

# ---------------------------------------------------------------------------
# Row 4: ML anomaly detection
# ---------------------------------------------------------------------------
st.subheader("ML Anomaly Detection (Isolation Forest)")
if not ml_df.empty:
    c7, c8 = st.columns([1, 2])
    with c7:
        st.metric("Logins Scored", f"{len(ml_df):,}")
        st.metric("Flagged Anomalous", f"{int(ml_df['is_anomaly'].sum()):,}")
        st.caption(
            "Model scores every login on hour of day, day of week, whether the source IP "
            "is new for that user, recent failed attempts, and 24 hour login velocity. It flags "
            "behavior that does not resemble the rest of the population, without needing any "
            "labeled attack data."
        )
    with c8:
        fig = px.scatter(
            ml_df, x="event_time", y="anomaly_score", color="is_anomaly",
            hover_data=["username"],
            color_discrete_map={True: "#B71C1C", False: "#4CAF50"},
            labels={"event_time": "Login Time", "anomaly_score": "Anomaly Score"},
        )
        fig.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, use_container_width=True)

    with st.expander("View flagged anomalous logins"):
        st.dataframe(
            ml_df[ml_df["is_anomaly"]].sort_values("anomaly_score", ascending=False),
            use_container_width=True,
        )
else:
    st.info("Run `python -m siem.ml.run` to generate anomaly scores.")

# ---------------------------------------------------------------------------
# Row 5: Alerts table
# ---------------------------------------------------------------------------
st.subheader("Security Alerts")
if not filtered_alerts.empty:
    st.dataframe(
        filtered_alerts[[
            "detected_at", "rule_name", "severity", "title", "username",
            "src_ip", "risk_score", "status",
        ]].sort_values("detected_at", ascending=False),
        use_container_width=True,
        height=400,
    )
else:
    st.info("No alerts match the current filters. Run `python -m siem.detection.run` to generate alerts.")
