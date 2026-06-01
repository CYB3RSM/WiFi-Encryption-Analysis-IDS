"""
Module 9: Visualization Dashboard
Interactive Streamlit dashboard for WiFi IDS analysis results
Shows: active devices, encryption usage, weak encryption alerts, traffic trends
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pandas as pd
import numpy as np

# ── Optional Streamlit import (degrades gracefully if not installed) ──────────
try:
    import streamlit as st
    STREAMLIT_AVAILABLE = True
except ImportError:
    STREAMLIT_AVAILABLE = False

try:
    import plotly.express as px
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


# ── Pipeline runner (cached) ──────────────────────────────────────────────────

def run_pipeline(n_packets: int = 5000):
    """Run the full IDS pipeline and return enriched DataFrame + analysis objects."""
    from traffic_acquisition import TrafficAcquisition
    from packet_parser import PacketParser
    from device_profiler import DeviceProfiler
    from protocol_analyzer import ProtocolAnalyzer
    from encryption_detector import EncryptionDetector
    from encryption_strength import EncryptionStrengthAnalyzer
    from behavioral_profiler import BehavioralProfiler
    from anomaly_detector import AnomalyDetector

    # Module 1 – Traffic acquisition
    acq = TrafficAcquisition()
    raw = acq.create_synthetic_dataset(n_packets)

    # Module 2 – Feature extraction
    parser = PacketParser(raw)
    features = parser.extract_all_features()

    # Module 3 – Device profiling
    profiler = DeviceProfiler(features)
    device_profiles = profiler.profile_devices()

    # Module 4 – Protocol analysis
    analyzer = ProtocolAnalyzer(features)
    proto_stats = analyzer.analyze_protocol_distribution()
    tls_handshakes = analyzer.analyze_tls_handshakes()

    # Module 5 – Encryption detection
    enc_detector = EncryptionDetector(features)
    enc_summary = enc_detector.detect_encrypted_traffic()

    # Module 6 – Encryption strength
    strength_analyzer = EncryptionStrengthAnalyzer(features)
    overall_strength = strength_analyzer.calculate_overall_strength()
    weak_connections = strength_analyzer.identify_weak_encryption_connections()

    # Module 7 – Behavioral profiling
    beh_profiler = BehavioralProfiler(features)
    beh_comparison = beh_profiler.compare_devices()
    unusual = beh_profiler.identify_unusual_behavior()

    # Module 8 – Anomaly detection
    anomaly_det = AnomalyDetector(features)
    anomaly_det.inject_anomalies(0.03)
    anomaly_det.rule_based_detection()
    eval_result = anomaly_det.evaluate_model()
    anomaly_df = anomaly_det.anomaly_results

    return {
        'features': features,
        'device_profiles': device_profiles,
        'proto_stats': proto_stats,
        'tls_handshakes': tls_handshakes,
        'enc_summary': enc_summary,
        'overall_strength': overall_strength,
        'weak_connections': weak_connections,
        'beh_comparison': beh_comparison,
        'unusual': unusual,
        'anomaly_df': anomaly_df,
        'eval_result': eval_result,
    }


# ── Standalone chart generation (no Streamlit) ───────────────────────────────

def generate_static_charts(data: dict, output_dir: str):
    """Generate static PNG charts using matplotlib/seaborn."""
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')

    os.makedirs(output_dir, exist_ok=True)
    features = data['features']

    # Chart 1: Protocol distribution
    fig, ax = plt.subplots(figsize=(8, 5))
    proto_counts = features['protocol'].value_counts()
    ax.bar(proto_counts.index, proto_counts.values, color='steelblue', edgecolor='white')
    ax.set_title('Protocol Distribution', fontsize=14, fontweight='bold')
    ax.set_xlabel('Protocol'); ax.set_ylabel('Packet Count')
    plt.tight_layout(); fig.savefig(f'{output_dir}/protocol_distribution.png', dpi=150)
    plt.close()

    # Chart 2: Encryption pie
    enc_val = features['encrypted_flag'].sum()
    plain_val = len(features) - enc_val
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie([enc_val, plain_val], labels=['Encrypted', 'Plaintext'],
           colors=['#2196F3', '#FF9800'], autopct='%1.1f%%', startangle=90)
    ax.set_title('Traffic Encryption Distribution', fontsize=13, fontweight='bold')
    plt.tight_layout(); fig.savefig(f'{output_dir}/encryption_distribution.png', dpi=150)
    plt.close()

    # Chart 3: TLS version breakdown
    encrypted = features[features['encrypted_flag'] == 1]
    if len(encrypted) > 0 and 'tls_version' in encrypted.columns:
        tls_counts = encrypted['tls_version'].value_counts()
        colors = ['#4CAF50' if v in ['TLS 1.3', 'TLS 1.2'] else '#F44336'
                  for v in tls_counts.index]
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.barh(tls_counts.index, tls_counts.values, color=colors)
        ax.set_title('TLS Version Distribution', fontsize=14, fontweight='bold')
        ax.set_xlabel('Session Count')
        plt.tight_layout(); fig.savefig(f'{output_dir}/tls_versions.png', dpi=150)
        plt.close()

    # Chart 4: Device encryption ratio
    dev = data['device_profiles']
    if dev is not None and len(dev) > 0:
        fig, ax = plt.subplots(figsize=(8, 5))
        colors = ['#4CAF50' if r >= 0.6 else '#F44336'
                  for r in dev['encrypted_traffic_ratio']]
        ax.bar(dev['device_ip'], dev['encrypted_traffic_ratio'], color=colors)
        ax.axhline(0.6, color='orange', linestyle='--', label='60% threshold')
        ax.set_title('Device Encryption Ratio', fontsize=14, fontweight='bold')
        ax.set_xticklabels(dev['device_ip'], rotation=30, ha='right')
        ax.set_ylabel('Encryption Ratio'); ax.legend()
        plt.tight_layout(); fig.savefig(f'{output_dir}/device_encryption.png', dpi=150)
        plt.close()

    # Chart 5: Anomaly score distribution
    adf = data.get('anomaly_df')
    if adf is not None and 'anomaly_score' in adf.columns:
        fig, ax = plt.subplots(figsize=(8, 5))
        normal = adf[adf['ml_anomaly'] == 0]['anomaly_score']
        anomalous = adf[adf['ml_anomaly'] == 1]['anomaly_score']
        ax.hist(normal, bins=40, alpha=0.7, color='steelblue', label='Normal')
        ax.hist(anomalous, bins=20, alpha=0.8, color='#F44336', label='Anomaly')
        ax.set_title('Isolation Forest Anomaly Score Distribution', fontsize=13, fontweight='bold')
        ax.set_xlabel('Anomaly Score'); ax.set_ylabel('Count'); ax.legend()
        plt.tight_layout(); fig.savefig(f'{output_dir}/anomaly_scores.png', dpi=150)
        plt.close()

    print(f"Charts saved to {output_dir}/")
    return output_dir


# ── Streamlit Dashboard ───────────────────────────────────────────────────────

def build_streamlit_app():
    """Build and render the full Streamlit dashboard."""
    if not STREAMLIT_AVAILABLE:
        print("Streamlit not installed. Run: pip install streamlit plotly")
        return

    st.set_page_config(
        page_title="WiFi IDS – Encryption Analysis Dashboard",
        page_icon="🔐",
        layout="wide"
    )
    st.title("🔐 WiFi Traffic Monitoring & Encryption Analysis System")
    st.caption("COMP-834 Intrusion Detection Systems | PAK-AUSTRIA Fachhochschule | Spring 2026")

    # Sidebar
    st.sidebar.header("⚙️ Pipeline Settings")
    n_packets = st.sidebar.slider("Packets to Generate", 1000, 10000, 5000, 500)
    show_anomalies_only = st.sidebar.checkbox("Show Anomalies Only", False)

    @st.cache_data
    def cached_pipeline(n):
        return run_pipeline(n)

    with st.spinner("Running analysis pipeline..."):
        data = cached_pipeline(n_packets)

    features = data['features']
    device_profiles = data['device_profiles']
    enc_summary = data['enc_summary']
    overall_strength = data['overall_strength']
    weak_connections = data['weak_connections']
    anomaly_df = data['anomaly_df']
    eval_result = data['eval_result']

    # ── KPI Cards ──────────────────────────────────────────────────────────
    st.subheader("📊 Key Performance Indicators")
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Packets", f"{enc_summary['total_packets']:,}")
    c2.metric("Encrypted", f"{enc_summary['encryption_percentage']}%")
    c3.metric("Encryption Score", f"{overall_strength.get('overall_score', 0):.1f}/100",
              delta=overall_strength.get('rating', ''))
    weak_count = len(weak_connections) if isinstance(weak_connections, pd.DataFrame) else 0
    c4.metric("Weak Connections ⚠️", f"{weak_count:,}", delta_color="inverse")
    ml_anomalies = int(anomaly_df['ml_anomaly'].sum()) if 'ml_anomaly' in anomaly_df.columns else 0
    c5.metric("ML Anomalies 🚨", f"{ml_anomalies}")
    f1 = eval_result.get('f1_score', 0) if eval_result else 0
    c6.metric("Model F1-Score", f"{f1:.2f}")

    st.markdown("---")

    # ── Row 1: Protocol & Encryption ──────────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📡 Protocol Distribution")
        proto_counts = features['protocol'].value_counts().reset_index()
        proto_counts.columns = ['Protocol', 'Count']
        fig = px.bar(proto_counts, x='Protocol', y='Count',
                     color='Protocol', title="Packet Count by Protocol",
                     color_discrete_sequence=px.colors.qualitative.Set2)
        fig.update_layout(showlegend=False, height=350)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("🔒 Encryption Distribution")
        enc_data = pd.DataFrame({
            'Type': ['Encrypted', 'Plaintext'],
            'Count': [enc_summary['encrypted_packets'], enc_summary['unencrypted_packets']]
        })
        fig = px.pie(enc_data, names='Type', values='Count',
                     color_discrete_map={'Encrypted': '#2196F3', 'Plaintext': '#FF9800'},
                     title="Encrypted vs Plaintext Traffic")
        fig.update_layout(height=350)
        st.plotly_chart(fig, use_container_width=True)

    # ── Row 2: TLS & Cipher Suite ─────────────────────────────────────────
    col3, col4 = st.columns(2)

    with col3:
        st.subheader("🛡️ TLS Version Analysis")
        encrypted = features[features['encrypted_flag'] == 1]
        if len(encrypted) > 0 and 'tls_version' in encrypted.columns:
            tls_counts = encrypted['tls_version'].value_counts().reset_index()
            tls_counts.columns = ['TLS Version', 'Count']
            color_map = {
                'TLS 1.3': '#4CAF50', 'TLS 1.2': '#8BC34A',
                'TLS 1.1': '#FF9800', 'TLS 1.0': '#FF5722', 'SSL 3.0': '#F44336'
            }
            tls_counts['Color'] = tls_counts['TLS Version'].map(color_map).fillna('#9E9E9E')
            fig = px.bar(tls_counts, x='Count', y='TLS Version', orientation='h',
                         color='TLS Version',
                         color_discrete_map=color_map,
                         title="TLS Version Distribution (red = deprecated)")
            fig.update_layout(height=350, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

    with col4:
        st.subheader("🔑 Cipher Suite Strength")
        if 'encryption_strength' in features.columns:
            strength_counts = features[features['encrypted_flag'] == 1]['encryption_strength'].value_counts().reset_index()
            strength_counts.columns = ['Strength', 'Count']
            color_map_s = {'Strong': '#4CAF50', 'Weak': '#FF9800', 'None': '#9E9E9E', 'Deprecated': '#F44336'}
            fig = px.pie(strength_counts, names='Strength', values='Count',
                         color='Strength', color_discrete_map=color_map_s,
                         title="Cipher Suite Strength Distribution")
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)

    # ── Row 3: Devices ────────────────────────────────────────────────────
    st.subheader("💻 Device Profiles")
    col5, col6 = st.columns(2)

    with col5:
        if device_profiles is not None and len(device_profiles) > 0:
            fig = px.bar(device_profiles, x='device_ip', y='encrypted_traffic_ratio',
                         color='inferred_type',
                         title="Device Encryption Ratio (green ≥ 0.6)",
                         labels={'device_ip': 'Device IP', 'encrypted_traffic_ratio': 'Encryption Ratio'})
            fig.add_hline(y=0.6, line_dash='dash', line_color='orange',
                          annotation_text='60% threshold')
            fig.update_layout(height=370)
            st.plotly_chart(fig, use_container_width=True)

    with col6:
        if device_profiles is not None and len(device_profiles) > 0:
            fig = px.scatter(device_profiles, x='packet_count', y='encrypted_traffic_ratio',
                             color='inferred_type', size='total_data_sent',
                             hover_data=['device_ip'],
                             title="Device Traffic Volume vs Encryption Ratio")
            fig.update_layout(height=370)
            st.plotly_chart(fig, use_container_width=True)

    # ── Row 4: Anomaly Detection ──────────────────────────────────────────
    st.subheader("🚨 ML Anomaly Detection (Isolation Forest)")
    col7, col8 = st.columns(2)

    with col7:
        if 'anomaly_score' in anomaly_df.columns and 'ml_anomaly' in anomaly_df.columns:
            fig = go.Figure()
            normal = anomaly_df[anomaly_df['ml_anomaly'] == 0]
            anom = anomaly_df[anomaly_df['ml_anomaly'] == 1]
            fig.add_trace(go.Histogram(x=normal['anomaly_score'], name='Normal',
                                       marker_color='steelblue', opacity=0.7, nbinsx=50))
            fig.add_trace(go.Histogram(x=anom['anomaly_score'], name='Anomaly',
                                       marker_color='red', opacity=0.8, nbinsx=30))
            fig.update_layout(barmode='overlay', title='Anomaly Score Distribution',
                               xaxis_title='Score', yaxis_title='Count', height=370)
            st.plotly_chart(fig, use_container_width=True)

    with col8:
        if eval_result:
            st.markdown("#### Model Evaluation")
            e1, e2, e3, e4 = st.columns(4)
            e1.metric("Accuracy", f"{eval_result['accuracy']:.1%}")
            e2.metric("Precision", f"{eval_result['precision']:.2f}")
            e3.metric("Recall", f"{eval_result['recall']:.2f}")
            e4.metric("F1-Score", f"{eval_result['f1_score']:.2f}")
            cm = eval_result['confusion_matrix']
            cm_df = pd.DataFrame(cm, index=['Normal', 'Anomaly'], columns=['Pred Normal', 'Pred Anomaly'])
            fig = px.imshow(cm_df, text_auto=True, color_continuous_scale='Blues',
                            title='Confusion Matrix')
            fig.update_layout(height=290)
            st.plotly_chart(fig, use_container_width=True)

    # ── Weak Encryption Alerts ────────────────────────────────────────────
    st.markdown("---")
    st.subheader("⚠️ Weak Encryption Alerts")
    if isinstance(weak_connections, pd.DataFrame) and len(weak_connections) > 0:
        st.error(f"🔴 {len(weak_connections)} connections detected using weak or deprecated encryption!")
        display_cols = [c for c in ['src_ip', 'dst_ip', 'dst_port', 'tls_version',
                                     'cipher_suite', 'tls_score', 'cipher_score', 'risk_level']
                        if c in weak_connections.columns]
        st.dataframe(weak_connections[display_cols].head(50), use_container_width=True)
    else:
        st.success("✅ No weak encryption connections detected!")

    # ── Raw Data Explorer ─────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("🔍 Traffic Data Explorer")
    df_display = anomaly_df if show_anomalies_only and 'ml_anomaly' in anomaly_df.columns else features
    if show_anomalies_only and 'ml_anomaly' in anomaly_df.columns:
        df_display = anomaly_df[anomaly_df['ml_anomaly'] == 1]

    filter_ip = st.selectbox("Filter by Source IP", ['All'] + list(features['src_ip'].unique()))
    if filter_ip != 'All':
        df_display = df_display[df_display['src_ip'] == filter_ip]

    st.dataframe(df_display.head(100), use_container_width=True)
    st.caption(f"Showing {min(100, len(df_display))} of {len(df_display)} records")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # When run directly via `python dashboard.py`, generate static charts
    print("Generating IDS analysis charts...")
    data = run_pipeline(5000)
    generate_static_charts(data, '/mnt/user-data/outputs/charts')
    print("Done. To launch interactive dashboard run:")
    print("  streamlit run dashboard.py")
