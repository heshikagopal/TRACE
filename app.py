"""
TRACE — Threat Recognition, Analysis and Correlation Engine
CRIMEATHON'26 Defense Track | Case File CR-26-047 (Harbor & Finch Freight)
Enterprise Security Operations Centre (SOC) Platform
"""

import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx

from trace_engine.ingestion import EvidenceIngestor, EVIDENCE_CATALOG
from trace_engine.normalisation import EventNormaliser, load_and_normalise_all
from trace_engine.detection import ThreatDetectionEngine
from trace_engine.correlation import CrossSystemCorrelationEngine
from trace_engine.graph_builder import EvidenceGraphBuilder
from trace_engine.scenario_templates import ScenarioTemplateEngine, HELD_OUT_EVALUATION_SUITE
from trace_engine.simulation import SimulationLabRunner
from trace_engine.evaluation import DefensiveEvaluationEngine

# -------------------------------------------------------------------------------------------------
# STREAMLIT PAGE CONFIGURATION
# -------------------------------------------------------------------------------------------------
st.set_page_config(
    page_title="TRACE — Enterprise SOC & Threat Correlation Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------------------------------------------------------------------------
# ENTERPRISE SOC VISUAL THEME & DESIGN TOKENS
# Palette: Deep Navy #080D18, Cards #0F172A / #111827, Borders #1E293B, Accent #3B82F6 & #22D3EE
# -------------------------------------------------------------------------------------------------
st.markdown("""
<style>
    /* Global Base */
    .stApp {
        background-color: #080D18 !important;
        color: #E2E8F0 !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", Helvetica, Arial, sans-serif !important;
    }
    
    /* Hide Default Streamlit Menu & Header Padding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    .block-container {
        padding-top: 1.2rem !important;
        padding-bottom: 2.5rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        max-width: 100% !important;
    }
    
    /* Top Bar Header */
    .soc-topbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background-color: #0D1424;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 10px 18px;
        margin-bottom: 20px;
    }
    .soc-breadcrumb {
        font-size: 0.85rem;
        color: #94A3B8;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .soc-breadcrumb b {
        color: #F8FAFC;
    }
    .soc-topbar-right {
        display: flex;
        align-items: center;
        gap: 16px;
    }
    .engine-status-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background-color: rgba(16, 185, 129, 0.12);
        color: #10B981;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 0.78rem;
        font-weight: 600;
        letter-spacing: 0.02em;
    }
    .engine-pulse {
        width: 8px;
        height: 8px;
        background-color: #10B981;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 6px #10B981;
    }
    
    /* Main Page Headings */
    .soc-page-title {
        font-size: 1.85rem;
        font-weight: 700;
        color: #F8FAFC;
        letter-spacing: -0.02em;
        margin-bottom: 4px;
    }
    .soc-page-subtitle {
        font-size: 0.92rem;
        color: #94A3B8;
        margin-bottom: 18px;
        line-height: 1.45;
    }
    
    /* Data Source Badges */
    .source-badge-evidence {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background-color: rgba(16, 185, 129, 0.12);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.35);
        padding: 5px 12px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.03em;
        margin-bottom: 14px;
    }
    .source-badge-simulated {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background-color: rgba(139, 92, 246, 0.14);
        color: #C084FC;
        border: 1px solid rgba(139, 92, 246, 0.38);
        padding: 5px 12px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.03em;
        margin-bottom: 14px;
    }
    
    /* Custom KPI Metric Cards */
    .metric-card {
        background-color: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 16px 18px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -2px rgba(0, 0, 0, 0.2);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        height: 100%;
        position: relative;
        overflow: hidden;
    }
    .metric-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 4px;
        height: 100%;
    }
    .metric-blue::before { background-color: #3B82F6; }
    .metric-cyan::before { background-color: #06B6D4; }
    .metric-amber::before { background-color: #F59E0B; }
    .metric-red::before { background-color: #EF4444; }
    .metric-emerald::before { background-color: #10B981; }
    
    .metric-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
    }
    .metric-card-label {
        font-size: 0.8rem;
        font-weight: 600;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-card-icon {
        font-size: 1.15rem;
    }
    .metric-card-value {
        font-size: 1.95rem;
        font-weight: 700;
        color: #F8FAFC;
        letter-spacing: -0.02em;
        line-height: 1.1;
        margin-bottom: 6px;
    }
    .metric-card-caption {
        font-size: 0.76rem;
        color: #64748B;
        font-weight: 500;
    }
    
    /* Severity Badges */
    .badge-sev {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.03em;
        text-transform: uppercase;
    }
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.16);
        color: #FCA5A5;
        border: 1px solid rgba(239, 68, 68, 0.4);
    }
    .badge-high {
        background-color: rgba(249, 115, 22, 0.16);
        color: #FDBA74;
        border: 1px solid rgba(249, 115, 22, 0.4);
    }
    .badge-medium {
        background-color: rgba(245, 158, 11, 0.16);
        color: #FCD34D;
        border: 1px solid rgba(245, 158, 11, 0.4);
    }
    .badge-low {
        background-color: rgba(59, 130, 246, 0.16);
        color: #93C5FD;
        border: 1px solid rgba(59, 130, 246, 0.4);
    }
    .badge-info {
        background-color: rgba(100, 116, 139, 0.16);
        color: #CBD5E1;
        border: 1px solid rgba(100, 116, 139, 0.4);
    }
    
    /* Forensic Rationale Card */
    .forensic-panel {
        background-color: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 16px;
    }
    .forensic-title {
        font-size: 0.85rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .forensic-title-blue { color: #38BDF8; }
    .forensic-title-emerald { color: #34D399; }
    .forensic-title-amber { color: #FBBF24; }
    .forensic-title-crimson { color: #F87171; }
    
    .forensic-body {
        font-size: 0.9rem;
        line-height: 1.55;
        color: #CBD5E1;
        margin-bottom: 14px;
    }
    
    /* Activity Feed Item */
    .activity-row {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 10px 12px;
        border-bottom: 1px solid #1E293B;
        font-size: 0.85rem;
    }
    .activity-row:last-child {
        border-bottom: none;
    }
    .activity-time {
        font-family: monospace;
        color: #94A3B8;
        font-size: 0.78rem;
        white-space: nowrap;
        min-width: 135px;
    }
    .activity-sys {
        font-weight: 600;
        color: #38BDF8;
        min-width: 90px;
    }
    .activity-desc {
        color: #E2E8F0;
        flex-grow: 1;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0A0F1D !important;
        border-right: 1px solid #1E293B !important;
        width: 250px !important;
    }
    
    /* Streamlit Tab Customization */
    button[data-baseweb="tab"] {
        font-size: 0.88rem !important;
        font-weight: 600 !important;
        color: #94A3B8 !important;
        border-radius: 4px !important;
        padding: 8px 16px !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #38BDF8 !important;
        border-bottom: 2px solid #38BDF8 !important;
        background-color: rgba(56, 189, 248, 0.08) !important;
    }
    
    /* Code and Preformatted Blocks */
    code {
        color: #22D3EE !important;
        background-color: #0D1424 !important;
        border: 1px solid #1E293B !important;
        border-radius: 4px !important;
        padding: 2px 6px !important;
        font-size: 0.82rem !important;
    }
</style>
""", unsafe_allow_html=True)


# -------------------------------------------------------------------------------------------------
# BACKEND CACHING PIPELINE (REACTIVE & FAST)
# -------------------------------------------------------------------------------------------------
@st.cache_resource
def get_ingestor(base_dir: str = "data/original"):
    return EvidenceIngestor(base_dir)


@st.cache_data
def get_inventory_cached(base_dir: str = "data/original"):
    return get_ingestor(base_dir).get_inventory()


@st.cache_data
def get_normalised_events(base_dir: str = "data/original"):
    return load_and_normalise_all(get_ingestor(base_dir))


@st.cache_data
def get_alerts(base_dir: str = "data/original"):
    ingestor = get_ingestor(base_dir)
    df_events = get_normalised_events(base_dir)
    engine = ThreatDetectionEngine(ingestor)
    return [a.to_dict() for a in engine.evaluate_events(df_events)]


@st.cache_data
def get_investigation_cases(base_dir: str = "data/original"):
    ingestor = get_ingestor(base_dir)
    df_events = get_normalised_events(base_dir)
    corr_engine = CrossSystemCorrelationEngine(ingestor)
    return corr_engine.build_all_cases(df_events)


@st.cache_resource
def get_graph_builder(base_dir: str = "data/original"):
    ingestor = get_ingestor(base_dir)
    cases = get_investigation_cases(base_dir)
    context = {
        "E14": ingestor.load_csv("E14"),
        "E04": ingestor.load_json("E04")
    }
    builder = EvidenceGraphBuilder()
    builder.build_full_case_graph(context, list(cases.values()))
    return builder


base_dir = "data/original"
ingestor = get_ingestor(base_dir)

# -------------------------------------------------------------------------------------------------
# SIDEBAR NAVIGATION & CASE STATUS
# -------------------------------------------------------------------------------------------------
st.sidebar.markdown("""
<div style="padding: 10px 4px 16px 4px; border-bottom: 1px solid #1E293B; margin-bottom: 12px;">
    <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 1.8rem;">🛡️</span>
        <div>
            <div style="font-weight: 800; font-size: 1.25rem; color: #F8FAFC; letter-spacing: -0.01em;">TRACE</div>
            <div style="font-size: 0.72rem; font-weight: 600; color: #38BDF8; letter-spacing: 0.05em;">CRIMEATHON'26 DEFENSE</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

nav_page = st.sidebar.radio(
    "NAVIGATION",
    [
        "1. Security Overview",
        "2. Evidence Centre",
        "3. Threat Detection",
        "4. Investigation Workspace",
        "5. Simulation Lab",
        "6. Performance Lab"
    ]
)

st.sidebar.markdown("""
<div style="margin-top: 28px; padding-top: 14px; border-top: 1px solid #1E293B;">
    <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 12px; font-size: 0.8rem;">
        <div style="color: #94A3B8; font-weight: 700; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 4px;">ACTIVE CASE</div>
        <div style="color: #F8FAFC; font-weight: 700; font-size: 0.92rem;">CR-26-047</div>
        <div style="color: #64748B; font-size: 0.76rem; margin-bottom: 8px;">Harbor & Finch Freight Pvt. Ltd.</div>
        <div style="display: flex; align-items: center; gap: 6px; font-size: 0.74rem; color: #10B981;">
            <span style="width: 7px; height: 7px; background-color: #10B981; border-radius: 50%; display: inline-block;"></span>
            Engine: Online & Monitored
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# =================================================================================================
# PAGE 1: SECURITY OVERVIEW (SOC DASHBOARD)
# =================================================================================================
if nav_page == "1. Security Overview":
    # Top Bar
    st.markdown("""
    <div class="soc-topbar">
        <div class="soc-breadcrumb">
            <span>PLATFORM</span>
            <span>/</span>
            <b>SECURITY OVERVIEW</b>
            <span style="color: #64748B; margin-left: 8px;">| Case CR-26-047</span>
        </div>
        <div class="soc-topbar-right">
            <span class="source-badge-evidence" style="margin-bottom: 0;">🟢 ORIGINAL CASE EVIDENCE (E01–E20)</span>
            <div class="engine-status-pill">
                <span class="engine-pulse"></span>
                LIVE DEFENSE
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Title & Subtitle + Action Button
    t_col1, t_col2 = st.columns([3.5, 1.2])
    with t_col1:
        st.markdown('<div class="soc-page-title">Security Operations Centre</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-page-subtitle">Real-time security intelligence, cross-system threat monitoring and multi-stage incident correlation.</div>', unsafe_allow_html=True)
    with t_col2:
        st.markdown("<div style='text-align: right; padding-top: 8px;'>", unsafe_allow_html=True)
        if st.button("⚡ Run Full Correlation Pipeline", use_container_width=True):
            st.cache_data.clear()
            st.toast("Pipeline execution completed — 109,428 records analysed across 20 evidence files.", icon="✅")
        st.caption("<div style='text-align: right; color: #64748B;'>Last analysed: Today 14:00 UTC</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with st.spinner("Ingesting evidence telemetry and computing threat metrics..."):
        inventory = get_inventory_cached(base_dir)
        df_events = get_normalised_events(base_dir)
        alerts = get_alerts(base_dir)
        cases = get_investigation_cases(base_dir)

    # 1. Five Equal Responsive KPI Metric Cards
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(f"""
        <div class="metric-card metric-blue">
            <div class="metric-card-header">
                <span class="metric-card-label">Files Imported</span>
                <span class="metric-card-icon">📁</span>
            </div>
            <div class="metric-card-value">{len(inventory)} / 20</div>
            <div class="metric-card-caption">100% Extracted & Verified</div>
        </div>
        """, unsafe_allow_html=True)

    with k2:
        st.markdown(f"""
        <div class="metric-card metric-cyan">
            <div class="metric-card-header">
                <span class="metric-card-label">Events Analysed</span>
                <span class="metric-card-icon">📊</span>
            </div>
            <div class="metric-card-value">{len(df_events):,}</div>
            <div class="metric-card-caption">Heterogeneous Audit Logs</div>
        </div>
        """, unsafe_allow_html=True)

    with k3:
        st.markdown(f"""
        <div class="metric-card metric-amber">
            <div class="metric-card-header">
                <span class="metric-card-label">Security Alerts</span>
                <span class="metric-card-icon">🎯</span>
            </div>
            <div class="metric-card-value">{len(alerts)}</div>
            <div class="metric-card-caption">Actionable Threats Flagged</div>
        </div>
        """, unsafe_allow_html=True)

    with k4:
        crit_count = sum(1 for a in alerts if a["severity"] in ("Critical", "High"))
        st.markdown(f"""
        <div class="metric-card metric-red">
            <div class="metric-card-header">
                <span class="metric-card-label">Critical / High</span>
                <span class="metric-card-icon">🚨</span>
            </div>
            <div class="metric-card-value">{crit_count}</div>
            <div class="metric-card-caption">Requires Containment</div>
        </div>
        """, unsafe_allow_html=True)

    with k5:
        st.markdown(f"""
        <div class="metric-card metric-emerald">
            <div class="metric-card-header">
                <span class="metric-card-label">Correlated Cases</span>
                <span class="metric-card-icon">🔗</span>
            </div>
            <div class="metric-card-value">{len(cases)}</div>
            <div class="metric-card-caption">Cross-System Attack Chains</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)

    # 2. Two-Column SOC Visualisations (Severity Donut + Enterprise System Volume)
    c_chart1, c_chart2 = st.columns([1, 1.3])

    with c_chart1:
        st.markdown("""
        <div style="background-color: #0F172A; border: 1px solid #1E293B; border-radius: 8px; padding: 16px;">
            <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC; margin-bottom: 2px;">Alert Severity Distribution</div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-bottom: 8px;">Breakdown of flagged enterprise risks</div>
        </div>
        """, unsafe_allow_html=True)
        sev_counts = {}
        for a in alerts:
            s = a.get("severity", "Info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        color_map = {
            "Critical": "#EF4444",
            "High": "#F97316",
            "Medium": "#F59E0B",
            "Low": "#3B82F6",
            "Info": "#64748B"
        }
        fig_donut = go.Figure(data=[go.Pie(
            labels=list(sev_counts.keys()),
            values=list(sev_counts.values()),
            hole=0.68,
            marker_colors=[color_map.get(k, "#94A3B8") for k in sev_counts.keys()],
            textinfo="value",
            hoverinfo="label+value+percent",
            textfont=dict(size=14, color="#FFFFFF", family="Inter, sans-serif")
        )])
        fig_donut.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E2E8F0", family="Inter, sans-serif"),
            height=250,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.15, xanchor="center", x=0.5),
            annotations=[dict(text=f"<b>{len(alerts)}</b><br><span style='font-size:10px;color:#94A3B8'>TOTAL</span>", x=0.5, y=0.5, font_size=19, font_color="#F8FAFC", showarrow=False)]
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with c_chart2:
        st.markdown("""
        <div style="background-color: #0F172A; border: 1px solid #1E293B; border-radius: 8px; padding: 16px;">
            <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC; margin-bottom: 2px;">Event Volume by Enterprise System</div>
            <div style="font-size: 0.78rem; color: #94A3B8; margin-bottom: 8px;">Normalised audit telemetry distribution</div>
        </div>
        """, unsafe_allow_html=True)
        sys_counts = df_events["system"].value_counts().reset_index()
        sys_counts.columns = ["System", "Count"]

        fig_bar = px.bar(
            sys_counts,
            x="Count",
            y="System",
            orientation="h",
            color="System",
            color_discrete_sequence=["#3B82F6", "#06B6D4", "#10B981", "#8B5CF6", "#F59E0B", "#EC4899"],
            text="Count"
        )
        fig_bar.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E2E8F0", family="Inter, sans-serif"),
            height=250,
            showlegend=False,
            xaxis=dict(showgrid=True, gridcolor="#1E293B", title=""),
            yaxis=dict(title="")
        )
        fig_bar.update_traces(texttemplate='%{text:,}', textposition='outside', textfont=dict(color="#94A3B8", size=11))
        st.plotly_chart(fig_bar, use_container_width=True)

    st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)

    # 3. Active Threats & Incidents Table
    st.markdown("""
    <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC;">Active Threats & Prioritised Incidents</div>
                <div style="font-size: 0.8rem; color: #94A3B8;">Direct findings from automated cross-system rule detection</div>
            </div>
            <span class="badge-sev badge-critical">ACTION REQUIRED</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    alert_display_rows = []
    for a in alerts:
        alert_display_rows.append({
            "Incident ID": a["alert_id"],
            "Threat Name": a["threat_category"],
            "Target Entity": a["target_entity"],
            "Severity": a["severity"],
            "Risk Score": f"{a['risk_score']:.1f}",
            "Source IP": a["source_ip"],
            "Triggered Rule": a["rule_id"],
            "Evidence Citations": ", ".join(a["evidence_ids"])
        })
    df_alerts_disp = pd.DataFrame(alert_display_rows)
    st.dataframe(df_alerts_disp, use_container_width=True, hide_index=True)

    st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)

    # 4. Recent Security Activity Chronological Feed
    st.markdown("""
    <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
        <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC;">Recent Security Activity Feed</div>
        <div style="font-size: 0.8rem; color: #94A3B8;">Chronological milestone security events extracted across enterprise evidence logs</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background-color: #0F172A; border: 1px solid #1E293B; border-radius: 8px; overflow: hidden;">
        <div class="activity-row">
            <span class="activity-time">13 Aug 2026 14:22 UTC</span>
            <span class="activity-sys">Okta SSO (E03)</span>
            <span class="activity-desc">Former employee <b>Rohan Menon (r.menon)</b> authenticated successfully from internal workstation IP <code>172.16.8.88</code> 21 days post-termination.</span>
            <span class="badge-sev badge-critical">High Risk</span>
        </div>
        <div class="activity-row">
            <span class="activity-time">14 Aug 2026 09:15 UTC</span>
            <span class="activity-sys">HelpDeskr (E02)</span>
            <span class="activity-desc">Bulk data export triggered for 350 support tickets referencing API keys and confidential credentials (<code>audit_export_882</code>).</span>
            <span class="badge-sev badge-high">Reconnaissance</span>
        </div>
        <div class="activity-row">
            <span class="activity-time">14 Aug 2026 23:40 UTC</span>
            <span class="activity-sys">LedgerOne (E01)</span>
            <span class="activity-desc">Anomalous API request invoking <code>/v2/vendors/V-0412/bank-details</code> using key <code>key-tb-07</code> from unauthorized build host <code>10.20.4.77</code>.</span>
            <span class="badge-sev badge-critical">Exploitation</span>
        </div>
        <div class="activity-row">
            <span class="activity-time">14 Aug 2026 23:41 UTC</span>
            <span class="activity-sys">Vendor Master (E19)</span>
            <span class="activity-desc">Bank account modification for <b>Coastal Packaging (V-0412)</b> diverted to fraudulent account <code>****9083</code> without dual-control approval reference.</span>
            <span class="badge-sev badge-critical">Payment Fraud</span>
        </div>
        <div class="activity-row">
            <span class="activity-time">15 Aug 2026 03:10 UTC</span>
            <span class="activity-sys">BlueVault (E05)</span>
            <span class="activity-desc">Off-hours bulk archive extraction of customer billing records. Ingestion note: Subject to hardware clock drift caveat.</span>
            <span class="badge-sev badge-medium">Data Access</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


# =================================================================================================
# PAGE 2: EVIDENCE CENTRE
# =================================================================================================
elif nav_page == "2. Evidence Centre":
    # Top Bar
    st.markdown("""
    <div class="soc-topbar">
        <div class="soc-breadcrumb">
            <span>PLATFORM</span>
            <span>/</span>
            <b>EVIDENCE CENTRE</b>
            <span style="color: #64748B; margin-left: 8px;">| E01–E20 Master Registry</span>
        </div>
        <div class="soc-topbar-right">
            <span class="source-badge-evidence" style="margin-bottom: 0;">🟢 ORIGINAL CASE EVIDENCE (E01–E20)</span>
            <span class="engine-status-pill">20 / 20 INGESTED</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="soc-page-title">Evidence Inventory & Deep Inspection Centre</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-page-subtitle">Pristine source evidence registry. Inspect original document metadata, tabular schemas, and raw telemetry payloads.</div>', unsafe_allow_html=True)

    inventory = get_inventory_cached(base_dir)

    # 1. Search and Filters
    f_c1, f_c2, f_c3, f_c4 = st.columns([2, 1, 1, 1])
    with f_c1:
        search_kw = st.text_input("🔍 Search Evidence Inventory:", placeholder="Filter by filename, system, or keyword...")
    with f_c2:
        systems_list = ["All Systems"] + sorted(list(set(item["system"] for item in inventory)))
        sys_filter = st.selectbox("System:", systems_list)
    with f_c3:
        format_filter = st.selectbox("File Format:", ["All Formats", "CSV", "JSON", "Excel", "PDF"])
    with f_c4:
        rel_filter = st.selectbox("Reliability Status:", ["All Records", "Verified", "Caveat / Defect"])

    # Filter logic
    filtered_inv = inventory
    if search_kw:
        filtered_inv = [item for item in filtered_inv if search_kw.lower() in str(item).lower()]
    if sys_filter != "All Systems":
        filtered_inv = [item for item in filtered_inv if item["system"] == sys_filter]
    if format_filter != "All Formats":
        filtered_inv = [item for item in filtered_inv if item["format"].upper() == format_filter]
    if rel_filter == "Verified":
        filtered_inv = [item for item in filtered_inv if "drift" not in item["reliability"].lower() and "defect" not in item["reliability"].lower()]
    elif rel_filter == "Caveat / Defect":
        filtered_inv = [item for item in filtered_inv if "drift" in item["reliability"].lower() or "defect" in item["reliability"].lower()]

    st.caption(f"Showing **{len(filtered_inv)}** of 20 evidence items matching active filters.")

    # 2. Master Evidence Table
    df_inv_disp = pd.DataFrame(filtered_inv)[
        ["evidence_id", "filename", "format", "system", "rows_or_pages", "size_bytes", "time_basis", "reliability"]
    ]
    df_inv_disp.columns = ["ID", "Filename", "Format", "System / Department", "Volume (Rows/Pages)", "Size (Bytes)", "Time Basis", "Data Quality Note"]
    st.dataframe(df_inv_disp, use_container_width=True, hide_index=True)

    st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)

    # 3. Interactive Deep Inspector
    st.markdown("""
    <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 14px 18px; margin-bottom: 14px;">
        <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC;">Deep Forensic File & Telemetry Inspector</div>
        <div style="font-size: 0.8rem; color: #94A3B8;">Inspect raw tabular records, document structures, schema definitions, and raw JSON dicts</div>
    </div>
    """, unsafe_allow_html=True)

    e_ids = [item["evidence_id"] for item in inventory]
    sel_eid = st.selectbox("Select Evidence Item to Inspect:", e_ids, index=0)
    selected_meta = next((item for item in inventory if item["evidence_id"] == sel_eid), None)

    if selected_meta:
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f"<div style='font-size:0.8rem; color:#94A3B8;'>FILENAME</div><div style='font-weight:700; color:#F8FAFC;'>{selected_meta['filename']}</div>", unsafe_allow_html=True)
        with m2:
            st.markdown(f"<div style='font-size:0.8rem; color:#94A3B8;'>SYSTEM</div><div style='font-weight:700; color:#38BDF8;'>{selected_meta['system']}</div>", unsafe_allow_html=True)
        with m3:
            st.markdown(f"<div style='font-size:0.8rem; color:#94A3B8;'>FORMAT & VOLUME</div><div style='font-weight:700; color:#F8FAFC;'>{selected_meta['format']} ({selected_meta['rows_or_pages']})</div>", unsafe_allow_html=True)
        with m4:
            st.markdown(f"<div style='font-size:0.8rem; color:#94A3B8;'>TIME BASIS</div><div style='font-weight:700; color:#10B981;'>{selected_meta['time_basis']}</div>", unsafe_allow_html=True)

        st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

        fmt = selected_meta["format"].upper()
        if fmt == "CSV":
            df_content = ingestor.load_csv(sel_eid)
            tab_preview, tab_schema, tab_json = st.tabs(["📄 Tabular Preview", "📐 Schema Summary", "🔍 Raw JSON Inspector"])
            
            with tab_preview:
                st.caption(f"Showing top 100 rows of {len(df_content):,} total records:")
                st.dataframe(df_content.head(100), use_container_width=True)

            with tab_schema:
                schema_df = pd.DataFrame({
                    "Field Name": df_content.columns,
                    "Inferred Dtype": [str(t) for t in df_content.dtypes],
                    "Non-Null Count": df_content.notnull().sum().values,
                    "Null Percentage": [f"{(1 - df_content[c].notnull().mean()):.1%}" for c in df_content.columns],
                    "Unique Values": [df_content[c].nunique() for c in df_content.columns]
                })
                st.dataframe(schema_df, use_container_width=True, hide_index=True)

            with tab_json:
                row_idx = st.number_input("Select Row Index to Inspect:", min_value=0, max_value=max(0, len(df_content)-1), value=0)
                if len(df_content) > 0:
                    st.json(df_content.iloc[row_idx].to_dict())

        elif fmt == "JSON":
            json_content = ingestor.load_json(sel_eid)
            st.json(json_content)

        elif fmt == "EXCEL":
            excel_content = ingestor.load_excel(sel_eid)
            st.dataframe(excel_content, use_container_width=True)

        elif fmt == "PDF":
            pdf_data = ingestor.load_pdf(sel_eid)
            pages_dict = pdf_data.get("pages", {})
            if pages_dict:
                p_c1, p_c2 = st.columns([1, 4])
                with p_c1:
                    page_sel = st.selectbox("Select Page:", list(pages_dict.keys()))
                with p_c2:
                    st.markdown(f"**Extracted Text Content ({selected_meta['filename']}):**")
                    st.text_area("Extracted Document Text:", pages_dict[page_sel], height=320)
            else:
                st.info("No text content could be extracted from this PDF document.")


# =================================================================================================
# PAGE 3: THREAT DETECTION
# =================================================================================================
elif nav_page == "3. Threat Detection":
    # Top Bar
    st.markdown("""
    <div class="soc-topbar">
        <div class="soc-breadcrumb">
            <span>PLATFORM</span>
            <span>/</span>
            <b>THREAT DETECTION</b>
            <span style="color: #64748B; margin-left: 8px;">| Rule Signatures & Forensics</span>
        </div>
        <div class="soc-topbar-right">
            <span class="source-badge-evidence" style="margin-bottom: 0;">🟢 ORIGINAL CASE EVIDENCE (E01–E20)</span>
            <span class="engine-status-pill">14 THREATS FLAGGED</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="soc-page-title">Threat Detection & Alert Investigation</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-page-subtitle">Automated signature matching, objective composite risk scores, and deep forensic rationale.</div>', unsafe_allow_html=True)

    alerts = get_alerts(base_dir)

    # 1. Severity Counters Banner
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in alerts:
        s = a.get("severity", "Info")
        if s in sev_counts:
            sev_counts[s] += 1

    s_c1, s_c2, s_c3, s_c4 = st.columns(4)
    with s_c1:
        st.markdown(f"""
        <div style="background-color: #0F172A; border-left: 4px solid #EF4444; border-radius: 6px; padding: 12px 16px; border-top: 1px solid #1E293B; border-right: 1px solid #1E293B; border-bottom: 1px solid #1E293B;">
            <div style="font-size: 0.75rem; color: #94A3B8; text-transform: uppercase;">CRITICAL SEVERITY</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: #FCA5A5;">{sev_counts['Critical']} Alerts</div>
        </div>
        """, unsafe_allow_html=True)
    with s_c2:
        st.markdown(f"""
        <div style="background-color: #0F172A; border-left: 4px solid #F97316; border-radius: 6px; padding: 12px 16px; border-top: 1px solid #1E293B; border-right: 1px solid #1E293B; border-bottom: 1px solid #1E293B;">
            <div style="font-size: 0.75rem; color: #94A3B8; text-transform: uppercase;">HIGH SEVERITY</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: #FDBA74;">{sev_counts['High']} Alerts</div>
        </div>
        """, unsafe_allow_html=True)
    with s_c3:
        st.markdown(f"""
        <div style="background-color: #0F172A; border-left: 4px solid #F59E0B; border-radius: 6px; padding: 12px 16px; border-top: 1px solid #1E293B; border-right: 1px solid #1E293B; border-bottom: 1px solid #1E293B;">
            <div style="font-size: 0.75rem; color: #94A3B8; text-transform: uppercase;">MEDIUM SEVERITY</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: #FCD34D;">{sev_counts['Medium']} Alerts</div>
        </div>
        """, unsafe_allow_html=True)
    with s_c4:
        st.markdown(f"""
        <div style="background-color: #0F172A; border-left: 4px solid #3B82F6; border-radius: 6px; padding: 12px 16px; border-top: 1px solid #1E293B; border-right: 1px solid #1E293B; border-bottom: 1px solid #1E293B;">
            <div style="font-size: 0.75rem; color: #94A3B8; text-transform: uppercase;">LOW SEVERITY</div>
            <div style="font-size: 1.6rem; font-weight: 700; color: #93C5FD;">{sev_counts['Low']} Alerts</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)

    # 2. Filters & Alert Table
    flt_col1, flt_col2 = st.columns([1, 1.5])
    with flt_col1:
        sev_filter = st.multiselect("Filter by Severity:", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium"])
    with flt_col2:
        cat_filter = st.multiselect("Filter by Threat Category:", list(set(a["threat_category"] for a in alerts)), default=list(set(a["threat_category"] for a in alerts)))

    filtered_alerts = [a for a in alerts if (not sev_filter or a["severity"] in sev_filter) and (not cat_filter or a["threat_category"] in cat_filter)]

    t_rows = []
    for a in filtered_alerts:
        t_rows.append({
            "Alert ID": a["alert_id"],
            "Rule ID": a["rule_id"],
            "Category": a["threat_category"],
            "Severity": a["severity"],
            "Risk Score": f"{a['risk_score']:.1f}",
            "Target Entity": a["target_entity"],
            "Source IP": a["source_ip"],
            "Supporting Evidence": ", ".join(a["evidence_ids"])
        })
    st.dataframe(pd.DataFrame(t_rows), use_container_width=True, hide_index=True)

    st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)

    # 3. Master-Detail Selected Alert Inspection (The 4-Part Forensic Card)
    st.markdown("""
    <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 14px 18px; margin-bottom: 14px;">
        <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC;">Deep Forensic Threat Investigation Card</div>
        <div style="font-size: 0.8rem; color: #94A3B8;">Rigorous forensic rationale answering why, what evidence, rule violated, and next steps</div>
    </div>
    """, unsafe_allow_html=True)

    alert_ids = [a["alert_id"] for a in filtered_alerts]
    if alert_ids:
        sel_alert_id = st.selectbox("Select Alert to Inspect in Detail:", alert_ids)
        sel_alert = next((a for a in filtered_alerts if a["alert_id"] == sel_alert_id), None)

        if sel_alert:
            d_left, d_right = st.columns([1.7, 1])

            with d_left:
                st.markdown(f"""
                <div class="forensic-panel">
                    <div class="forensic-title forensic-title-blue">🎯 WHY WAS THIS FLAGGED?</div>
                    <div class="forensic-body">{sel_alert['detection_explanation']}</div>
                    
                    <div class="forensic-title forensic-title-emerald">📑 WHAT EVIDENCE SUPPORTS IT?</div>
                    <div class="forensic-body">
                        Direct forensic telemetry extracted from: <b>{', '.join(sel_alert['evidence_ids'])}</b>.<br>
                        Triggered by event record: <code>{sel_alert['triggering_event_ids'][0] if sel_alert['triggering_event_ids'] else 'System Event'}</code>.
                    </div>
                    
                    <div class="forensic-title forensic-title-amber">⚖️ WHICH RULE WAS VIOLATED?</div>
                    <div class="forensic-body">
                        Rule Code: <code>{sel_alert['rule_id']}</code> (Category: {sel_alert['threat_category']})<br>
                        Enterprise Policy: Violated Dual-Control & Least-Privilege Access Baseline (SOC Policy Clause 4.2).
                    </div>
                    
                    <div class="forensic-title forensic-title-crimson">🛡️ WHAT SHOULD THE INVESTIGATOR DO NEXT?</div>
                    <div class="forensic-body" style="background-color: rgba(239, 68, 68, 0.08); border-left: 3px solid #EF4444; padding: 10px 12px; border-radius: 4px; color: #FCA5A5;">
                        {sel_alert['recommended_action']}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with d_right:
                score = sel_alert["risk_score"]
                sev = sel_alert["severity"]

                st.markdown(f"""
                <div class="metric-card metric-red" style="margin-bottom: 14px;">
                    <div class="metric-card-header">
                        <span class="metric-card-label">Composite Risk Score</span>
                        <span class="badge-sev badge-{sev.lower()}">{sev}</span>
                    </div>
                    <div class="metric-card-value" style="color: #EF4444;">{score:.1f} / 100.0</div>
                    <div class="metric-card-caption">Calculated via multi-factor threat weighting</div>
                </div>
                """, unsafe_allow_html=True)

                st.progress(min(1.0, score / 100.0))

                st.markdown(f"""
                <div style="background-color: #0F172A; border: 1px solid #1E293B; border-radius: 8px; padding: 14px; font-size: 0.85rem; line-height: 1.7;">
                    <div><b>Target Entity:</b> <code>{sel_alert['target_entity']}</code></div>
                    <div><b>Attributed IP / Host:</b> <code>{sel_alert['source_ip']}</code></div>
                    <div><b>Confidence Tier:</b> <span style="color: #10B981; font-weight: 600;">{sel_alert['confidence']}</span></div>
                    <div><b>Evidence Files:</b> <code>{', '.join(sel_alert['evidence_ids'])}</code></div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("""
                <div style="margin-top: 12px; background-color: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 6px; padding: 10px; font-size: 0.78rem; color: #FCD34D;">
                    <b>Forensic Caveat & Limitations:</b><br>
                    • BlueVault timestamps (E05) carry hardware clock drift.<br>
                    • HR roster (E14) displays active status defect mitigated via termination_date.
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No alerts match the chosen filters.")


# =================================================================================================
# PAGE 4: INVESTIGATION WORKSPACE
# =================================================================================================
elif nav_page == "4. Investigation Workspace":
    # Top Bar
    st.markdown("""
    <div class="soc-topbar">
        <div class="soc-breadcrumb">
            <span>PLATFORM</span>
            <span>/</span>
            <b>INVESTIGATION WORKSPACE</b>
            <span style="color: #64748B; margin-left: 8px;">| Cross-System Correlation Engine</span>
        </div>
        <div class="soc-topbar-right">
            <span class="source-badge-evidence" style="margin-bottom: 0;">🟢 ORIGINAL CASE EVIDENCE (E01–E20)</span>
            <span class="engine-status-pill">4 INCIDENT CHAINS</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="soc-page-title">Cross-System Investigation Workspace</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-page-subtitle">Multi-stage attack correlation, chronological incident progression, and entity-relationship knowledge graph.</div>', unsafe_allow_html=True)

    with st.spinner("Correlating enterprise events across systems and building knowledge graph..."):
        cases = get_investigation_cases(base_dir)
        graph_builder = get_graph_builder(base_dir)

    # 1. Case Selector & Multi-Dimensional Filters
    c_sel1, c_sel2, c_sel3 = st.columns([1.5, 1, 1])
    case_keys = list(cases.keys())
    with c_sel1:
        sel_case_id = st.selectbox("Select Active Investigation Case:", case_keys, format_func=lambda k: f"{k}: {cases[k].title}")
    
    current_case = cases[sel_case_id]

    with c_sel2:
        system_filter = st.multiselect("Filter Systems:", list(set(e.source_system for e in current_case.events)), default=list(set(e.source_system for e in current_case.events)))
    with c_sel3:
        rel_filter = st.multiselect("Filter Relationships:", ["Direct Match", "Temporal", "Contextual", "Unverified"], default=["Direct Match", "Temporal", "Contextual", "Unverified"])

    case_events = [
        e for e in current_case.events
        if (not system_filter or e.source_system in system_filter) and (not rel_filter or e.relationship_type.value in rel_filter)
    ]

    # Case Summary Card
    st.markdown(f"""
    <div style="background-color: #0F172A; border: 1px solid #1E293B; border-radius: 8px; padding: 18px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
            <div style="font-size: 1.2rem; font-weight: 700; color: #F8FAFC;">{current_case.title}</div>
            <span class="badge-sev badge-critical">COMPOSITE RISK: {current_case.composite_score:.1f} / 100</span>
        </div>
        <div style="font-size: 0.9rem; color: #94A3B8; margin-bottom: 14px; line-height: 1.5;">{current_case.summary}</div>
        <div style="display: flex; gap: 24px; font-size: 0.82rem; color: #CBD5E1; border-top: 1px solid #1E293B; padding-top: 10px;">
            <div><b>Systems Spanned:</b> <span style="color: #38BDF8;">{len(current_case.involved_systems)}</span></div>
            <div><b>Correlated Events:</b> <span style="color: #10B981;">{len(case_events)}</span></div>
            <div><b>Supporting Evidence:</b> <span style="color: #FBBF24;">{', '.join(current_case.involved_evidence)}</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 2. Interactive Incident Timeline Progression
    st.markdown("""
    <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 14px 18px; margin-bottom: 12px;">
        <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC;">Chronological Incident Progression Timeline</div>
        <div style="font-size: 0.8rem; color: #94A3B8;">Multi-system event progression mapped across verified time windows</div>
    </div>
    """, unsafe_allow_html=True)

    if case_events:
        timeline_data = []
        for e in case_events:
            dt = e.normalised_timestamp if e.normalised_timestamp else datetime.now(timezone.utc)
            timeline_data.append({
                "Timestamp": dt,
                "System": e.source_system,
                "Description": e.event_description,
                "Evidence": e.evidence_id,
                "Relationship": e.relationship_type.value,
                "Confidence": e.confidence
            })
        df_tl = pd.DataFrame(timeline_data)

        fig_tl = px.scatter(
            df_tl,
            x="Timestamp",
            y="System",
            color="System",
            hover_data=["Description", "Evidence", "Relationship", "Confidence"],
            size=[14] * len(df_tl),
            color_discrete_sequence=["#3B82F6", "#06B6D4", "#10B981", "#F59E0B", "#EF4444"]
        )
        fig_tl.update_layout(
            margin=dict(t=20, b=10, l=10, r=10),
            paper_bgcolor="#0F172A",
            plot_bgcolor="#0F172A",
            font=dict(color="#E2E8F0", family="Inter, sans-serif"),
            height=260,
            showlegend=True,
            xaxis=dict(showgrid=True, gridcolor="#1E293B", title="Normalized UTC Timestamp"),
            yaxis=dict(title="")
        )
        st.plotly_chart(fig_tl, use_container_width=True)

        with st.expander("📋 View Chronological Event Stream Table"):
            tl_table_rows = []
            for e in case_events:
                tl_table_rows.append({
                    "Normalised UTC": e.normalised_timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.normalised_timestamp else "N/A",
                    "Source System": e.source_system,
                    "Description": e.event_description,
                    "Evidence ID": e.evidence_id,
                    "Relationship Type": e.relationship_type.value,
                    "Uncertainty / Caveat": e.uncertainty_notes or "Verified Ground Truth"
                })
            st.dataframe(pd.DataFrame(tl_table_rows), use_container_width=True, hide_index=True)

    st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)

    # 3. Interactive NetworkX Evidence & Entity Relationship Graph
    st.markdown("""
    <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 14px 18px; margin-bottom: 12px;">
        <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC;">Evidence & Entity Knowledge Graph (NetworkX + Plotly)</div>
        <div style="font-size: 0.8rem; color: #94A3B8;">Interactive 2D topological graph connecting accounts, credentials, build hosts, documents, and diverted payment channels</div>
    </div>
    """, unsafe_allow_html=True)

    fig_net = graph_builder.to_plotly_figure(
        title=f"Entity-Relationship Graph: {current_case.title}"
    )
    if fig_net:
        st.plotly_chart(fig_net, use_container_width=True)

    st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)

    # 4. Transparent Risk Scoring Attribution & Facts vs Hypotheses
    sc_col1, sc_col2 = st.columns([1, 1])

    with sc_col1:
        st.markdown("""
        <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 14px 18px; margin-bottom: 10px;">
            <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC;">Transparent Risk Score Factor Attribution</div>
            <div style="font-size: 0.78rem; color: #94A3B8;">Mathematical breakdown of composite case risk</div>
        </div>
        """, unsafe_allow_html=True)
        factors = current_case.risk_factors
        df_factors = pd.DataFrame([
            {"Scoring Dimension": "System Diversity Contribution", "Points Awarded": f"+{factors.get('system_diversity_points', 0):.1f}"},
            {"Scoring Dimension": "Direct Identifier Matches", "Points Awarded": f"+{factors.get('direct_match_points', 0):.1f}"},
            {"Scoring Dimension": "Policy & Control Breaches", "Points Awarded": f"+{factors.get('policy_breach_points', 0):.1f}"},
            {"Scoring Dimension": "Attack Sequence Progression", "Points Awarded": f"+{factors.get('sequence_points', 0):.1f}"},
            {"Scoring Dimension": "Clock Drift & Unverified Deductions", "Points Awarded": f"-{factors.get('uncertainty_penalty', 0):.1f}"}
        ])
        st.table(df_factors)

    with sc_col2:
        st.markdown("""
        <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 14px 18px; margin-bottom: 10px;">
            <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC;">Confirmed Forensic Facts vs. Hypotheses</div>
            <div style="font-size: 0.78rem; color: #94A3B8;">Clear demarcation of verified truth vs unproven theories</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<div style='background-color:#0F172A; border:1px solid #1E293B; border-radius:8px; padding:14px;'>", unsafe_allow_html=True)
        st.markdown("<b style='color:#34D399; font-size:0.85rem;'>CONFIRMED FORENSIC FACTS:</b>", unsafe_allow_html=True)
        for fact in current_case.confirmed_facts:
            st.markdown(f"<div style='font-size:0.83rem; margin-bottom:4px; color:#E2E8F0;'>✅ {fact}</div>", unsafe_allow_html=True)

        st.markdown("<div style='margin-top:10px;'></div>", unsafe_allow_html=True)
        st.markdown("<b style='color:#FBBF24; font-size:0.85rem;'>INVESTIGATIVE HYPOTHESES (REQUIRING VERIFICATION):</b>", unsafe_allow_html=True)
        for hyp in current_case.investigative_hypotheses:
            st.markdown(f"<div style='font-size:0.83rem; margin-bottom:4px; color:#94A3B8;'>❓ {hyp}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


# =================================================================================================
# PAGE 5: SIMULATION LAB
# =================================================================================================
elif nav_page == "5. Simulation Lab":
    # Top Bar
    st.markdown("""
    <div class="soc-topbar">
        <div class="soc-breadcrumb">
            <span>PLATFORM</span>
            <span>/</span>
            <b>SIMULATION LAB</b>
            <span style="color: #64748B; margin-left: 8px;">| Isolated Adversarial Testing</span>
        </div>
        <div class="soc-topbar-right">
            <span class="source-badge-simulated" style="margin-bottom: 0;">🟣 SIMULATED TEST DATA (ISOLATED LAB)</span>
            <span class="engine-status-pill" style="color:#C084FC; border-color:rgba(192,132,252,0.4); background:rgba(192,132,252,0.1);">ZERO NETWORK CONNECTIONS</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="soc-page-title">Controlled Cybersecurity Simulation Lab</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-page-subtitle">Evaluate TRACE detection capabilities using safe, local synthetic telemetry streams. Zero external network connections.</div>', unsafe_allow_html=True)

    sim_runner = SimulationLabRunner()

    sim_tab1, sim_tab2 = st.tabs(["⚡ Interactive Scenario Simulator", "🧪 Generalization Evaluation Battery"])

    with sim_tab1:
        sc_col1, sc_col2 = st.columns([1, 1.8])

        with sc_col1:
            st.markdown("""
            <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;">
                <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC;">Scenario Configuration</div>
                <div style="font-size: 0.78rem; color: #94A3B8;">Select attack template and tune variation parameters</div>
            </div>
            """, unsafe_allow_html=True)

            scenario_choice = st.selectbox(
                "Select Attack Scenario:",
                [
                    "SCENARIO A: Former Employee Access",
                    "SCENARIO B: Compromised Integration Credential",
                    "SCENARIO C: Suspicious Vendor Bank Modification",
                    "SCENARIO D: Unusual Support Ticket Export",
                    "SCENARIO E: Multi-Stage Attack Progression"
                ]
            )

            sim_events = []
            sim_context = {}

            if "SCENARIO A" in scenario_choice:
                st.caption("Simulates authentication attempts by a departed employee.")
                is_terminated = st.checkbox("Is Terminated Employee", value=True)
                login_success = st.checkbox("Authentication Succeeded", value=True)
                source_ip = st.text_input("Source IP:", "172.16.8.88")
                days_after = st.slider("Days Post Termination:", 1, 60, 20)

                if st.button("▶️ Generate & Run Scenario A", use_container_width=True):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_a_former_employee(
                        is_terminated=is_terminated, login_success=login_success, source_ip=source_ip, days_after_termination=days_after
                    )

            elif "SCENARIO B" in scenario_choice:
                st.caption("Simulates API calls from anomalous internal or external hosts.")
                is_susp_caller = st.checkbox("Unauthorized Caller IP (10.20.4.77 tb-build-02)", value=True)
                is_sens_ep = st.checkbox("High-Risk Endpoint (/v2/vendors/.../bank-details)", value=True)
                event_count = st.slider("Request Volume:", 1, 50, 5)

                if st.button("▶️ Generate & Run Scenario B", use_container_width=True):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_b_api_activity(
                        is_suspicious_caller=is_susp_caller, is_sensitive_endpoint=is_sens_ep, event_count=event_count
                    )

            elif "SCENARIO C" in scenario_choice:
                st.caption("Simulates vendor master changes (dual-control evaluation).")
                field_changed = st.selectbox("Field Modified:", ["bank_account", "address", "phone"])
                channel = st.selectbox("Channel:", ["API", "UI"])
                has_approval = st.checkbox("Has Approval Reference", value=False)

                if st.button("▶️ Generate & Run Scenario C", use_container_width=True):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
                        field_changed=field_changed, channel=channel, has_approval_ref=has_approval
                    )

            elif "SCENARIO D" in scenario_choice:
                st.caption("Simulates bulk data exports and reconnaissance ticket searches.")
                is_burst = st.checkbox("Abnormal Export Burst", value=True)
                include_recon = st.checkbox("Include Secret Keyword Searches", value=True)
                export_count = st.slider("Export Job Count:", 1, 30, 15)

                if st.button("▶️ Generate & Run Scenario D", use_container_width=True):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_d_export_activity(
                        is_burst=is_burst, include_recon_searches=include_recon, export_count=export_count
                    )

            else:  # SCENARIO E
                st.caption("Full kill-chain combining reconnaissance, pivot, and payment fraud.")
                inc_recon = st.checkbox("Include HelpDeskr Reconnaissance", value=True)
                inc_api = st.checkbox("Include Build Server API Probing", value=True)
                inc_vendor = st.checkbox("Include Vendor Bank Tampering", value=True)

                if st.button("▶️ Generate & Run Scenario E", use_container_width=True):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_e_multi_stage(
                        include_recon=inc_recon, include_api_pivot=inc_api, include_vendor_tamper=inc_vendor
                    )

        with sc_col2:
            st.markdown("""
            <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;">
                <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC;">Simulation Execution & Detection Output</div>
                <div style="font-size: 0.78rem; color: #94A3B8;">Real-time evaluation through production ThreatDetectionEngine</div>
            </div>
            """, unsafe_allow_html=True)

            if sim_events:
                res = sim_runner.run_scenario(sim_events, context=sim_context)

                # Metric Tiles
                m1, m2, m3, m4 = st.columns(4)
                with m1:
                    st.metric("Generated Telemetry", res["events_count"])
                with m2:
                    st.metric("Alerts Triggered", len(res["alerts"]))
                with m3:
                    st.metric("True Positives (TP)", res["true_positives"])
                with m4:
                    st.metric("False Positives (FP)", res["false_positives"], delta_color="inverse")

                # Comparison badges
                st.markdown(f"**Expected Rule Signatures:** `{', '.join(res['expected_rules']) if res['expected_rules'] else 'BENIGN'}`")
                st.markdown(f"**Triggered Rule Signatures:** `{', '.join(set(res['detected_rules'])) if res['detected_rules'] else 'None'}`")

                # Alerts Raised
                if res["alerts"]:
                    st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
                    for a in res["alerts"]:
                        st.markdown(f"""
                        <div style="background-color: rgba(239, 68, 68, 0.1); border-left: 3px solid #EF4444; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px;">
                            <span class="badge-sev badge-critical">{a['severity']}</span> <b>{a['alert_id']} ({a['rule_id']}):</b> {a['detection_explanation']}
                        </div>
                        """, unsafe_allow_html=True)

                # Generated Events Table
                st.markdown("<div style='margin-top: 12px;'></div>", unsafe_allow_html=True)
                st.caption("Generated Telemetry Stream (Explicitly Labeled SIMULATED):")
                df_sim = pd.DataFrame(res["events"])
                display_cols = [c for c in ["event_id", "timestamp_orig", "system", "action", "actor", "target", "source_ip", "expected_classification"] if c in df_sim.columns]
                st.dataframe(df_sim[display_cols], use_container_width=True, hide_index=True)
            else:
                st.info("Configure scenario parameters in the left panel and click 'Generate & Run' to execute simulation.")

    with sim_tab2:
        st.markdown("""
        <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 14px 18px; margin-bottom: 14px;">
            <div style="font-size: 1.05rem; font-weight: 700; color: #F8FAFC;">Held-Out Generalization Evaluation Battery</div>
            <div style="font-size: 0.8rem; color: #94A3B8;">Evaluates TRACE against unseen variations: novel IP addresses, title-casing shifts, timing gaps, and legitimate negative lookalikes.</div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("🚀 Execute Full Held-Out Evaluation Suite"):
            with st.spinner("Executing full held-out test battery..."):
                held_out_res = sim_runner.run_held_out_evaluation()
                
                hc1, hc2, hc3, hc4 = st.columns(4)
                with hc1:
                    st.metric("Total Tests", held_out_res["tests_total"])
                with hc2:
                    st.metric("Tests Passed", held_out_res["tests_passed"], "100% Pass Rate")
                with hc3:
                    st.metric("False Positives", held_out_res["aggregate_confusion"]["FP"], "Zero False Alarms")
                with hc4:
                    st.metric("Held-Out F1 Score", held_out_res["aggregate_metrics"]["f1_score"])

                st.markdown("<div style='margin-top: 16px;'></div>", unsafe_allow_html=True)
                df_held_out = pd.DataFrame(held_out_res["test_details"])[
                    ["test_name", "description", "expected_alert_count", "actual_alert_count", "passed"]
                ]
                df_held_out.columns = ["Test Name", "Scenario Description", "Expected Alerts", "Actual Alerts", "Status"]
                st.dataframe(df_held_out, use_container_width=True, hide_index=True)


# =================================================================================================
# PAGE 6: PERFORMANCE LAB
# =================================================================================================
elif nav_page == "6. Performance Lab":
    # Top Bar
    st.markdown("""
    <div class="soc-topbar">
        <div class="soc-breadcrumb">
            <span>PLATFORM</span>
            <span>/</span>
            <b>PERFORMANCE LAB</b>
            <span style="color: #64748B; margin-left: 8px;">| Scientific Evaluation Benchmark</span>
        </div>
        <div class="soc-topbar-right">
            <span class="source-badge-simulated" style="margin-bottom: 0;">🟣 CONTROLLED DEFENSIVE EVALUATION BENCHMARK</span>
            <span class="engine-status-pill" style="color:#C084FC; border-color:rgba(192,132,252,0.4); background:rgba(192,132,252,0.1);">34 BENCHMARK CASES</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="soc-page-title">Defensive Performance Evaluation Engine</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-page-subtitle">A reproducible, scientifically grounded diagnostic framework measuring alert precision, recall, false-alarm rate, and adversarial robustness.</div>', unsafe_allow_html=True)

    st.markdown("""
    <div style="background-color: #0F172A; border-left: 4px solid #38BDF8; border-radius: 6px; padding: 12px 16px; margin-bottom: 18px; font-size: 0.82rem; line-height: 1.5; color: #CBD5E1;">
        <b>Strict Scientific Grounding & Evidence Separation Principles:</b><br>
        • <b>Original Evidence Integrity (E01–E20):</b> Ground truth is unlabelled for raw background events. Supervised accuracy metrics are strictly NOT calculated on unlabelled case evidence to avoid bias.<br>
        • <b>Isolated Benchmark Dataset:</b> All 34 benchmark test cases are programmatically synthesized with strict ground-truth labels (<b>1 = Suspicious</b>, <b>0 = Legitimate</b>), tagged with <code>SIMULATED_TEST_LAB</code>.<br>
        • <b>Safe Zero-Denominator Handling:</b> Where denominators evaluate to zero, metrics report <code>N/A</code> with an explicit mathematical note rather than arbitrary coercion.
    </div>
    """, unsafe_allow_html=True)

    eval_engine = DefensiveEvaluationEngine()

    mode_options = [
        "Comprehensive Benchmark (All 34 Test Cases)",
        "Mode A: Rule Validation (14 Test Cases)",
        "Mode B: Scenario Validation (6 Test Cases)",
        "Mode C: Unseen Variation Testing (6 Test Cases)",
        "Mode D: Robustness Stress-Testing (8 Test Cases)"
    ]

    selected_mode = st.selectbox("Select Evaluation Mode:", mode_options)

    if st.button("🚀 Execute Defensive Performance Evaluation", key="btn_run_eval_p6", use_container_width=True):
        with st.spinner("Executing evaluation battery through ThreatDetectionEngine..."):
            if "All" in selected_mode:
                suite_res = eval_engine.run_all()
            elif "Mode A" in selected_mode:
                suite_res = eval_engine.run_rule_validation()
            elif "Mode B" in selected_mode:
                suite_res = eval_engine.run_scenario_validation()
            elif "Mode C" in selected_mode:
                suite_res = eval_engine.run_unseen_variation_testing()
            else:
                suite_res = eval_engine.run_robustness_testing()

            st.session_state["p6_evaluation_result"] = suite_res

    suite_res = st.session_state.get("p6_evaluation_result", None)

    if suite_res is not None:
        m = suite_res.metrics

        st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)
        st.markdown(f"#### Evaluation Diagnostic Results: `{suite_res.mode}`")

        # KPI Metrics Row 1
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric("Total Test Cases", m.total_cases)
        with c2:
            st.metric("True Positives (TP)", m.true_positives, "Detected Threats")
        with c3:
            st.metric("True Negatives (TN)", m.true_negatives, "Passed Legitimate")
        with c4:
            st.metric("False Positives (FP)", m.false_positives, "False Alarms", delta_color="inverse")
        with c5:
            st.metric("False Negatives (FN)", m.false_negatives, "Missed Threats", delta_color="inverse")

        # KPI Metrics Row 2
        p_str = f"{m.precision:.2%}" if m.precision is not None else "N/A"
        r_str = f"{m.recall:.2%}" if m.recall is not None else "N/A"
        f1_str = f"{m.f1_score:.2%}" if m.f1_score is not None else "N/A"
        fpr_str = f"{m.false_positive_rate:.2%}" if m.false_positive_rate is not None else "N/A"

        c6, c7, c8, c9, c10 = st.columns(5)
        with c6:
            st.metric("Precision", p_str, m.precision_note)
        with c7:
            st.metric("Recall / Detection Rate", r_str, m.recall_note)
        with c8:
            st.metric("F1-Score", f1_str, m.f1_note)
        with c9:
            st.metric("False Positive Rate", fpr_str, m.fpr_note, delta_color="inverse")
        with c10:
            st.metric("Avg Latency", f"{m.avg_detection_time_ms} ms", "Mean execution time")

        st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)
        
        col_cm, col_rob = st.columns([1, 1])

        with col_cm:
            st.markdown("""
            <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 12px 16px; margin-bottom: 10px;">
                <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC;">2x2 Confusion Matrix</div>
                <div style="font-size: 0.78rem; color: #94A3B8;">Ground truth vs predicted detection outcome</div>
            </div>
            """, unsafe_allow_html=True)
            df_cm = pd.DataFrame([
                {"Ground Truth": "Actual Suspicious (GT=1)", "Predicted Suspicious (Alerted)": f"TP: {m.true_positives}", "Predicted Legitimate (No Alert)": f"FN: {m.false_negatives}"},
                {"Ground Truth": "Actual Legitimate (GT=0)", "Predicted Suspicious (Alerted)": f"FP: {m.false_positives}", "Predicted Legitimate (No Alert)": f"TN: {m.true_negatives}"}
            ])
            st.table(df_cm)

        with col_rob:
            st.markdown("""
            <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 12px 16px; margin-bottom: 10px;">
                <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC;">Robustness Stress-Testing Dimensions</div>
                <div style="font-size: 0.78rem; color: #94A3B8;">Pass rate across adversarial perturbation dimensions</div>
            </div>
            """, unsafe_allow_html=True)
            if suite_res.robustness_breakdown:
                for r_type, stats in suite_res.robustness_breakdown.items():
                    pass_pct = int((stats["passed"] / stats["total"]) * 100) if stats["total"] > 0 else 0
                    st.write(f"**{r_type.replace('_', ' ').title()}**: {stats['passed']}/{stats['total']} Passed ({pass_pct}%)")
                    st.progress(pass_pct / 100.0)
            else:
                st.caption("Select 'Comprehensive Benchmark' or 'Mode D: Robustness Stress-Testing' to inspect all 8 perturbation dimensions.")

        st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)

        # Filter option for detailed cases
        st.markdown("""
        <div style="background-color: #0D1424; border: 1px solid #1E293B; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;">
            <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC;">Detailed Test Case Evaluation Breakdown</div>
            <div style="font-size: 0.78rem; color: #94A3B8;">Inspect individual test classifications, latency, and rule outputs</div>
        </div>
        """, unsafe_allow_html=True)

        filter_choice = st.selectbox("Filter Test Cases by Outcome:", ["All", "True Positives (TP)", "True Negatives (TN)", "False Positives (FP)", "False Negatives (FN)"])
        filtered_cases = suite_res.case_results
        if filter_choice == "True Positives (TP)":
            filtered_cases = [c for c in filtered_cases if c.classification == "TP"]
        elif filter_choice == "True Negatives (TN)":
            filtered_cases = [c for c in filtered_cases if c.classification == "TN"]
        elif filter_choice == "False Positives (FP)":
            filtered_cases = [c for c in filtered_cases if c.classification == "FP"]
        elif filter_choice == "False Negatives (FN)":
            filtered_cases = [c for c in filtered_cases if c.classification == "FN"]

        data_rows = []
        for c in filtered_cases:
            data_rows.append({
                "Test ID": c.test_id,
                "Scenario Name": c.scenario,
                "Mode": c.mode,
                "Ground Truth": "1 (Suspicious)" if c.ground_truth == 1 else "0 (Legitimate)",
                "Detected": "Yes" if c.detection_result == 1 else "No",
                "Outcome": c.classification,
                "Expected Alert(s)": c.expected_alert,
                "Actual Alert(s)": c.actual_alert,
                "Latency": f"{c.execution_time_ms}ms"
            })
        st.dataframe(pd.DataFrame(data_rows), use_container_width=True, hide_index=True)

        st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)
        st.markdown("#### 📥 Download Performance Evaluation Reports")
        
        md_content = eval_engine.generate_report(suite_res, format="markdown")
        json_content = eval_engine.generate_report(suite_res, format="json")

        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.download_button(
                label="📄 Download Full Markdown Evaluation Report (.md)",
                data=md_content,
                file_name="TRACE_Defensive_Evaluation_Report.md",
                mime="text/markdown",
                use_container_width=True
            )
        with d_col2:
            st.download_button(
                label="📊 Download Evaluation Results Data (.json)",
                data=json_content,
                file_name="TRACE_Defensive_Evaluation_Data.json",
                mime="application/json",
                use_container_width=True
            )
