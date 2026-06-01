"""
Module 9: Interactive Visualization Dashboard
WiFi IDS — Encryption Analysis Dashboard (Streamlit)

Run: streamlit run dashboard/app.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../modules"))

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WiFi IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Load / Generate Data ──────────────────────────────────────────────────────
@st.cache_data
def load_data():
    from main_pipeline import run_pipeline
    return run_pipeline(5000, out_dir="../dataset")

with st.spinner("Running IDS pipeline..."):
    results = load_data()

df            = results["df"]
profiles      = results["profiles"]
beh           = results["beh_profiles"]
dns_df        = results["dns_df"]
tls_df        = results["tls_df"]
enc_sum       = results["enc_summary"]
ml_metrics    = results["ml_metrics"]
strength_rpt  = results["strength_report"]

df["timestamp"] = pd.to_datetime(df["timestamp"])

# ── Sidebar ────────────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ WiFi IDS Controls")
st.sidebar.markdown("---")

device_filter = st.sidebar.multiselect(
    "Filter by Device IP",
    options=df["src_ip"].unique().tolist(),
    default=df["src_ip"].unique().tolist(),
)

proto_filter = st.sidebar.multiselect(
    "Filter by Protocol",
    options=df["protocol"].unique().tolist(),
    default=df["protocol"].unique().tolist(),
)

show_anomalies = st.sidebar.checkbox("Highlight Anomalies Only", value=False)
st.sidebar.markdown("---")
st.sidebar.markdown("**Course:** COMP-834 IDS")
st.sidebar.markdown("**PAF-IAST Spring 2026**")

# Apply filters
dff = df[df["src_ip"].isin(device_filter) & df["protocol"].isin(proto_filter)]
if show_anomalies:
    dff = dff[dff["ml_anomaly"] == 1]

# ── Header ─────────────────────────────────────────────────────────────────────
st.title("🛡️ WiFi Traffic Monitoring & Encryption Analysis Dashboard")
st.markdown("**Intrusion Detection System | COMP-834 | PAF-IAST Spring 2026**")
st.markdown("---")

# ── KPI Row ────────────────────────────────────────────────────────────────────
k1, k2, k3, k4, k5 = st.columns(5)

with k1:
    st.metric("Total Packets", f"{enc_sum['total']:,}")
with k2:
    st.metric("Encrypted", f"{enc_sum['enc_pct']}%",
              delta=f"{enc_sum['encrypted']:,} pkts")
with k3:
    st.metric("Plaintext", f"{enc_sum['plain_pct']}%",
              delta=f"{enc_sum['unencrypted']:,} pkts", delta_color="inverse")
with k4:
    weak_count = (df["overall_strength"].isin(["weak", "deprecated"])).sum()
    st.metric("⚠️ Weak/Deprecated TLS", f"{weak_count:,}", delta_color="inverse")
with k5:
    st.metric("🔴 ML Anomalies", f"{df['ml_anomaly'].sum():,}",
              delta=f"F1={ml_metrics.get('f1', 0):.2f}", delta_color="inverse")

st.markdown("---")

# ── Row 1: Encryption Pie + Traffic Over Time ──────────────────────────────────
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("🔐 Encryption Distribution")
    pie_data = dff["enc_class"].value_counts().reset_index()
    pie_data.columns = ["Type", "Count"]
    color_map = {"Encrypted": "#2ecc71", "Unencrypted": "#e74c3c", "Likely VPN": "#f39c12"}
    fig_pie = px.pie(
        pie_data, names="Type", values="Count",
        color="Type", color_discrete_map=color_map,
        hole=0.45,
    )
    fig_pie.update_traces(textposition="inside", textinfo="percent+label")
    fig_pie.update_layout(showlegend=True, margin=dict(t=0, b=0, l=0, r=0), height=320)
    st.plotly_chart(fig_pie, use_container_width=True)

with col2:
    st.subheader("📈 Traffic Volume Over Time")
    ts = (dff.set_index("timestamp")
             .resample("30s")["packet_size"]
             .count()
             .reset_index()
             .rename(columns={"packet_size": "packets", "timestamp": "time"}))
    anom_ts = (dff[dff["ml_anomaly"] == 1]
               .set_index("timestamp")
               .resample("30s")["ml_anomaly"]
               .sum()
               .reset_index()
               .rename(columns={"ml_anomaly": "anomalies", "timestamp": "time"}))
    fig_ts = go.Figure()
    fig_ts.add_trace(go.Scatter(x=ts["time"], y=ts["packets"],
                                mode="lines", name="Packets",
                                line=dict(color="#3498db", width=2)))
    if not anom_ts.empty:
        merged = ts.merge(anom_ts, on="time", how="left").fillna(0)
        fig_ts.add_trace(go.Bar(x=merged["time"], y=merged["anomalies"],
                                name="Anomalies", marker_color="red", opacity=0.7,
                                yaxis="y2"))
    fig_ts.update_layout(
        height=320, margin=dict(t=10, b=40),
        yaxis=dict(title="Packets"),
        yaxis2=dict(title="Anomalies", overlaying="y", side="right"),
        legend=dict(orientation="h", y=-0.2),
    )
    st.plotly_chart(fig_ts, use_container_width=True)

# ── Row 2: Protocol Bar + TLS Version Distribution ────────────────────────────
col3, col4 = st.columns(2)

with col3:
    st.subheader("📡 Protocol Distribution")
    proto_counts = dff["protocol"].value_counts().reset_index()
    proto_counts.columns = ["Protocol", "Count"]
    proto_color = {
        "HTTPS": "#2ecc71", "TLS": "#27ae60", "QUIC": "#1abc9c",
        "HTTP":  "#e74c3c", "DNS": "#f39c12", "TCP": "#3498db",
        "UDP": "#9b59b6", "ARP": "#95a5a6", "ICMP": "#bdc3c7",
    }
    fig_proto = px.bar(
        proto_counts, x="Protocol", y="Count",
        color="Protocol", color_discrete_map=proto_color,
        text="Count",
    )
    fig_proto.update_layout(showlegend=False, height=320, margin=dict(t=10, b=40))
    st.plotly_chart(fig_proto, use_container_width=True)

with col4:
    st.subheader("🔒 TLS Version Usage")
    tls_data = dff[dff["tls_version"] != ""]["tls_version"].value_counts().reset_index()
    tls_data.columns = ["TLS Version", "Count"]
    tls_color_map = {
        "TLSv1.3": "#2ecc71", "TLSv1.2": "#f39c12",
        "TLSv1.1": "#e67e22", "TLSv1.0": "#e74c3c",
    }
    fig_tls = px.bar(
        tls_data, x="TLS Version", y="Count",
        color="TLS Version", color_discrete_map=tls_color_map,
        text="Count",
    )
    fig_tls.update_layout(showlegend=False, height=320, margin=dict(t=10, b=40))
    st.plotly_chart(fig_tls, use_container_width=True)

st.markdown("---")

# ── Row 3: Device Table + Encryption Strength ─────────────────────────────────
col5, col6 = st.columns([3, 2])

with col5:
    st.subheader("💻 Device-Wise Encryption Usage")
    dev_display = profiles[[
        "src_ip", "device_type", "total_packets", "enc_pct",
        "anomaly_count",
    ]].copy()
    dev_display.columns = ["IP", "Device Type", "Packets", "Encrypted %", "Anomalies"]
    dev_display["Encrypted %"] = dev_display["Encrypted %"].apply(lambda x: f"{x:.1f}%")

    def color_row(row):
        if float(row["Encrypted %"].replace("%","")) < 30:
            return ["background-color: #ffeaa7"] * len(row)
        if int(row["Anomalies"]) > 2:
            return ["background-color: #fab1a0"] * len(row)
        return [""] * len(row)

    st.dataframe(
        dev_display.style.apply(color_row, axis=1),
        use_container_width=True, height=280,
    )

with col6:
    st.subheader("🔑 Cipher Strength Breakdown")
    strength_counts = dff[dff["overall_strength"] != ""]["overall_strength"].value_counts()
    strength_df = strength_counts.reset_index()
    strength_df.columns = ["Strength", "Count"]
    strength_color = {"strong": "#2ecc71", "weak": "#f39c12", "deprecated": "#e74c3c", "unknown": "#95a5a6"}
    fig_str = px.pie(
        strength_df, names="Strength", values="Count",
        color="Strength", color_discrete_map=strength_color,
        hole=0.4,
    )
    fig_str.update_layout(height=280, margin=dict(t=0, b=0, l=0, r=0))
    st.plotly_chart(fig_str, use_container_width=True)

st.markdown("---")

# ── Row 4: Weak Encryption Alerts ─────────────────────────────────────────────
st.subheader("⚠️ Weak & Deprecated Encryption Alerts")
weak_df = dff[dff["overall_strength"].isin(["weak", "deprecated"])][
    ["timestamp", "src_ip", "device_type", "dst_ip",
     "tls_version", "cipher_suite", "overall_strength"]
].sort_values("timestamp", ascending=False).head(50)

if weak_df.empty:
    st.success("No weak encryption detected in current filter.")
else:
    st.warning(f"⚠️  {len(weak_df)} weak/deprecated sessions detected (showing top 50)")

    def highlight_strength(val):
        if val == "deprecated": return "background-color:#fab1a0; color:#c0392b; font-weight:bold"
        if val == "weak":       return "background-color:#ffeaa7; color:#d35400"
        return ""

    st.dataframe(
        weak_df.style.map(highlight_strength, subset=["overall_strength"]),
        use_container_width=True, height=250,
    )

st.markdown("---")

# ── Row 5: DNS + ML Anomaly Scatter ───────────────────────────────────────────
col7, col8 = st.columns(2)

with col7:
    st.subheader("🌐 Top DNS Queries")
    top_dns = dns_df.head(15)
    fig_dns = px.bar(
        top_dns, x="count", y="dns_query",
        orientation="h",
        color="suspicious",
        color_discrete_map={True: "#e74c3c", False: "#3498db"},
        labels={"dns_query": "Domain", "count": "Queries", "suspicious": "Suspicious"},
    )
    fig_dns.update_layout(height=350, margin=dict(t=10, b=10), showlegend=True)
    st.plotly_chart(fig_dns, use_container_width=True)

with col8:
    st.subheader("🤖 ML Anomaly Score Distribution")
    fig_anom = px.scatter(
        dff.sample(min(2000, len(dff))),
        x="packet_size", y="anomaly_score",
        color=dff.loc[dff.index[:min(2000,len(dff))], "ml_anomaly"].astype(str)
               if len(dff) >= 2000 else dff["ml_anomaly"].astype(str),
        color_discrete_map={"0": "#3498db", "1": "#e74c3c"},
        labels={"packet_size": "Packet Size", "anomaly_score": "Anomaly Score",
                "color": "Anomaly"},
        opacity=0.6, size_max=8,
    )
    fig_anom.update_layout(height=350, margin=dict(t=10, b=10))
    st.plotly_chart(fig_anom, use_container_width=True)

st.markdown("---")

# ── Row 6: Raw Data Explorer ──────────────────────────────────────────────────
with st.expander("📋 Raw Traffic Data Explorer"):
    display_cols = ["timestamp", "src_ip", "dst_ip", "protocol",
                    "packet_size", "enc_class", "tls_version",
                    "cipher_suite", "overall_strength", "ml_anomaly"]
    st.dataframe(dff[display_cols].head(500), use_container_width=True)

st.caption("PAF-IAST | COMP-834 Intrusion Detection Systems | Spring 2026 | Dr Muhammad Zeeshan")
