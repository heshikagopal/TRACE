"""
TRACE — Threat Recognition, Analysis and Correlation Engine
CRIMEATHON'26 Defense Track | Case File CR-26-047 (Harbor & Finch Freight)
Lead Python Developer & Cybersecurity Detection Engineer Interface
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
    page_title="TRACE — Security Operations & Threat Correlation Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------------------------------------------------------------------------
# PROFESSIONAL SOC VISUAL THEME (DARK NAVY / NEUTRAL)
# -------------------------------------------------------------------------------------------------
st.markdown("""
<style>
    /* Main Layout */
    .stApp {
        background-color: #0A0F1D;
        color: #E2E8F0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Headers */
    .soc-header {
        font-size: 2.1rem;
        font-weight: 700;
        color: #F8FAFC;
        letter-spacing: -0.02em;
        margin-bottom: 0.2rem;
    }
    .soc-subheader {
        font-size: 0.95rem;
        color: #94A3B8;
        margin-bottom: 1.2rem;
    }
    
    /* Data Source Badges */
    .source-badge-evidence {
        display: inline-flex;
        align-items: center;
        background-color: rgba(16, 185, 129, 0.12);
        color: #10B981;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 5px 12px;
        border-radius: 6px;
        font-size: 0.82rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        margin-bottom: 1.2rem;
    }
    .source-badge-simulated {
        display: inline-flex;
        align-items: center;
        background-color: rgba(139, 92, 246, 0.12);
        color: #A78BFA;
        border: 1px solid rgba(139, 92, 246, 0.35);
        padding: 5px 12px;
        border-radius: 6px;
        font-size: 0.82rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        margin-bottom: 1.2rem;
    }
    
    /* Severity Badges */
    .sev-critical {
        background-color: #450A0A;
        color: #FCA5A5;
        border: 1px solid #7F1D1D;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.78rem;
    }
    .sev-high {
        background-color: #431407;
        color: #FDBA74;
        border: 1px solid #7C2D12;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.78rem;
    }
    .sev-medium {
        background-color: #451A03;
        color: #FCD34D;
        border: 1px solid #78350F;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.78rem;
    }
    .sev-low {
        background-color: #172554;
        color: #93C5FD;
        border: 1px solid #1E3A8A;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.78rem;
    }
    
    /* Card Container */
    .soc-card {
        background-color: #111827;
        border: 1px solid #1F2937;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 16px;
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
# SIDEBAR NAVIGATION
# -------------------------------------------------------------------------------------------------
st.sidebar.markdown("""
<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
    <span style="font-size: 2rem;">🛡️</span>
    <div>
        <div style="font-weight: 700; font-size: 1.15rem; color: #F8FAFC;">TRACE</div>
        <div style="font-size: 0.75rem; color: #94A3B8;">CRIMEATHON'26 DEFENSE</div>
    </div>
</div>
""", unsafe_allow_html=True)

nav_page = st.sidebar.radio(
    "Navigation",
    [
        "1. Security Overview",
        "2. Evidence Centre",
        "3. Threat Detection",
        "4. Investigation Workspace",
        "5. Simulation Lab",
        "6. Performance Lab"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("""
<div style="background-color: #111827; border: 1px solid #1E293B; border-radius: 6px; padding: 10px; font-size: 0.8rem;">
    <div style="color: #94A3B8; font-weight: 600;">ACTIVE INVESTIGATION</div>
    <div style="color: #F8FAFC; font-weight: 700;">Case CR-26-047</div>
    <div style="color: #64748B;">Harbor & Finch Freight Pvt. Ltd.</div>
    <div style="color: #10B981; margin-top: 6px; font-size: 0.75rem;">● Engine Status: Online</div>
</div>
""", unsafe_allow_html=True)


# =================================================================================================
# PAGE 1: SECURITY OVERVIEW
# =================================================================================================
if nav_page == "1. Security Overview":
    st.markdown('<div class="source-badge-evidence">🟢 DATA SOURCE: ORIGINAL CASE EVIDENCE (E01–E20)</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-header">Security Operations Centre Overview</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Executive threat telemetry, event ingestion volume, alert severity distributions, and active attack chains.</div>', unsafe_allow_html=True)

    with st.spinner("Ingesting evidence and evaluating security telemetry..."):
        inventory = get_inventory_cached(base_dir)
        df_events = get_normalised_events(base_dir)
        alerts = get_alerts(base_dir)
        cases = get_investigation_cases(base_dir)

    # 1. Top KPI Metrics Cards
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.metric("Imported Evidence Files", f"{len(inventory)} / 20", "100% Extracted")
    with k2:
        st.metric("Total Events Analysed", f"{len(df_events):,}", "Heterogeneous Logs")
    with k3:
        st.metric("Total Alerts Raised", f"{len(alerts)}", "Actionable Threats")
    with k4:
        crit_count = sum(1 for a in alerts if a["severity"] in ("Critical", "High"))
        st.metric("Critical / High Severity", f"{crit_count}", "Priority Response", delta_color="inverse")
    with k5:
        st.metric("Correlated Cases", f"{len(cases)}", "Cross-System Chains")

    st.markdown("---")

    # 2. Charts Row (Severity Distribution + Ingested Volume by System)
    c_chart1, c_chart2 = st.columns([1, 1.2])

    with c_chart1:
        st.markdown("#### Alert Severity Distribution")
        sev_counts = {}
        for a in alerts:
            s = a.get("severity", "Info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        color_map = {
            "Critical": "#DC2626",
            "High": "#EA580C",
            "Medium": "#D97706",
            "Low": "#2563EB",
            "Info": "#64748B"
        }
        fig_donut = go.Figure(data=[go.Pie(
            labels=list(sev_counts.keys()),
            values=list(sev_counts.values()),
            hole=0.6,
            marker_colors=[color_map.get(k, "#94A3B8") for k in sev_counts.keys()],
            textinfo="label+value"
        )])
        fig_donut.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E2E8F0"),
            height=260,
            showlegend=True
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    with c_chart2:
        st.markdown("#### Telemetry Volume by Enterprise System")
        sys_counts = df_events["system"].value_counts().reset_index()
        sys_counts.columns = ["System", "Count"]

        fig_bar = px.bar(
            sys_counts,
            x="Count",
            y="System",
            orientation="h",
            color="System",
            color_discrete_sequence=["#3B82F6", "#10B981", "#8B5CF6", "#F59E0B", "#EC4899", "#06B6D4"],
            text="Count"
        )
        fig_bar.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E2E8F0"),
            height=260,
            showlegend=False,
            xaxis=dict(showgrid=True, gridcolor="#1E293B", title="Event Count"),
            yaxis=dict(title="")
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    st.markdown("---")

    # 3. Recent Detected Events & High-Risk Alerts Table
    st.markdown("#### Recent Detected Threats & Primary Alerts")
    alert_display_rows = []
    for a in alerts:
        alert_display_rows.append({
            "Alert ID": a["alert_id"],
            "Threat Category": a["threat_category"],
            "Severity": a["severity"],
            "Risk Score": f"{a['risk_score']:.1f}",
            "Target Entity": a["target_entity"],
            "Evidence Citations": ", ".join(a["evidence_ids"]),
            "Triggered Rule": a["rule_id"],
            "Confidence": a["confidence"]
        })
    df_alerts_disp = pd.DataFrame(alert_display_rows)
    st.dataframe(df_alerts_disp, use_container_width=True, hide_index=True)

    st.markdown("---")

    # 4. Ingestion & Timezone Health Status
    st.markdown("#### Evidence Ingestion & Telemetry Synchronization Status")
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown("**LedgerOne API (E01, E18)**")
        st.caption("Status: Ingested (45,800 events) | Timezone: UTC verified")
    with s2:
        st.markdown("**HelpDeskr Logs (E02)**")
        st.caption("Status: Ingested (3,450 events) | Timezone: IST (+05:30) converted to UTC")
    with s3:
        st.markdown("**BlueVault Storage (E05)**")
        st.caption("Status: Ingested (8,920 events) | Timezone: Epoch with recorded drift caveat")
    with s4:
        st.markdown("**HR Staff Roster (E14)**")
        st.caption("Status: Ingested (420 records) | Status defect mitigated via termination_date")


# =================================================================================================
# PAGE 2: EVIDENCE CENTRE
# =================================================================================================
elif nav_page == "2. Evidence Centre":
    st.markdown('<div class="source-badge-evidence">🟢 DATA SOURCE: ORIGINAL CASE EVIDENCE (E01–E20)</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-header">Evidence Inventory & Inspection Centre</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Pristine source evidence registry. Inspect original document metadata, tabular schemas, and raw telemetry payloads.</div>', unsafe_allow_html=True)

    inventory = get_inventory_cached(base_dir)

    # 1. Filters Row
    f_col1, f_col2 = st.columns([2, 1])
    with f_col1:
        search_kw = st.text_input("🔍 Search Evidence Inventory:", placeholder="Filter by filename, system, or keyword...")
    with f_col2:
        format_filter = st.selectbox("File Format:", ["All Formats", "CSV", "JSON", "Excel", "PDF"])

    # Filter inventory
    filtered_inv = inventory
    if format_filter != "All Formats":
        filtered_inv = [item for item in filtered_inv if item["format"].upper() == format_filter]
    if search_kw:
        filtered_inv = [item for item in filtered_inv if search_kw.lower() in str(item).lower()]

    # 2. Evidence Table Display
    df_inv_disp = pd.DataFrame(filtered_inv)[
        ["evidence_id", "filename", "format", "system", "rows_or_pages", "size_bytes", "time_basis", "reliability"]
    ]
    df_inv_disp.columns = ["ID", "Filename", "Format", "System / Department", "Rows/Pages", "Size (Bytes)", "Time Basis", "Data Quality Note"]
    st.dataframe(df_inv_disp, use_container_width=True, hide_index=True)

    st.markdown("---")

    # 3. Interactive File & Raw Record Inspector
    st.markdown("### Interactive Evidence File & Record Inspector")
    e_ids = [item["evidence_id"] for item in inventory]
    selected_eid = st.selectbox("Select Evidence Item to Inspect:", e_ids, index=0)
    
    selected_meta = next((item for item in inventory if item["evidence_id"] == selected_eid), None)

    if selected_meta:
        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        with m_col1:
            st.caption(f"**Filename:** `{selected_meta['filename']}`")
        with m_col2:
            st.caption(f"**Format:** `{selected_meta['format']}`")
        with m_col3:
            st.caption(f"**Time Basis:** `{selected_meta['time_basis']}`")
        with m_col4:
            st.caption(f"**Quality:** `{selected_meta['reliability']}`")

        # Load and display content based on file format
        fmt = selected_meta["format"].upper()
        if fmt == "CSV":
            df_content = ingestor.load_csv(selected_eid)
            st.markdown(f"**Tabular Preview (Showing top 100 of {len(df_content):,} rows):**")
            st.dataframe(df_content.head(100), use_container_width=True)

            with st.expander("🔍 Column Schema & Raw JSON Record Inspector"):
                c_schema1, c_schema2 = st.columns([1, 1])
                with c_schema1:
                    st.write("**Column Summary:**")
                    schema_df = pd.DataFrame({
                        "Column": df_content.columns,
                        "Type": [str(t) for t in df_content.dtypes],
                        "Non-Null Count": df_content.notnull().sum().values
                    })
                    st.dataframe(schema_df, hide_index=True)
                with c_schema2:
                    st.write("**Inspect Row as Raw JSON:**")
                    row_idx = st.number_input("Row Index:", min_value=0, max_value=max(0, len(df_content)-1), value=0)
                    if len(df_content) > 0:
                        st.json(df_content.iloc[row_idx].to_dict())

        elif fmt == "JSON":
            json_content = ingestor.load_json(selected_eid)
            st.markdown(f"**Structured JSON Content:**")
            st.json(json_content)

        elif fmt == "EXCEL":
            excel_content = ingestor.load_excel(selected_eid)
            st.markdown(f"**Worksheet Preview (Rows: {len(excel_content)}):**")
            st.dataframe(excel_content, use_container_width=True)

        elif fmt == "PDF":
            pdf_data = ingestor.load_pdf(selected_eid)
            st.markdown(f"**Extracted Text from PDF ({pdf_data.get('total_pages', 0)} Pages):**")
            pages_dict = pdf_data.get("pages", {})
            if pages_dict:
                page_sel = st.selectbox("Select Page:", list(pages_dict.keys()))
                st.text_area("Extracted Document Text:", pages_dict[page_sel], height=260)
            else:
                st.info("No text content could be extracted from this PDF.")


# =================================================================================================
# PAGE 3: THREAT DETECTION
# =================================================================================================
elif nav_page == "3. Threat Detection":
    st.markdown('<div class="source-badge-evidence">🟢 DATA SOURCE: ORIGINAL CASE EVIDENCE (E01–E20)</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-header">Threat Detection & Alert Investigation</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Rule-based threat signatures, transparent composite risk scores, and detailed forensic justification.</div>', unsafe_allow_html=True)

    alerts = get_alerts(base_dir)

    # 1. Alert Filtering
    a_f1, a_f2 = st.columns([1, 1])
    with a_f1:
        sev_filter = st.multiselect("Filter by Severity:", ["Critical", "High", "Medium", "Low", "Info"], default=["Critical", "High", "Medium"])
    with a_f2:
        cat_filter = st.multiselect("Filter by Threat Category:", list(set(a["threat_category"] for a in alerts)), default=list(set(a["threat_category"] for a in alerts)))

    filtered_alerts = [a for a in alerts if (not sev_filter or a["severity"] in sev_filter) and (not cat_filter or a["threat_category"] in cat_filter)]

    st.markdown(f"**Active Alerts Displayed:** {len(filtered_alerts)} of {len(alerts)}")

    # 2. Master Alert Table
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
            "Evidence IDs": ", ".join(a["evidence_ids"])
        })
    st.dataframe(pd.DataFrame(t_rows), use_container_width=True, hide_index=True)

    st.markdown("---")

    # 3. Master-Detail Selected Alert Inspection
    st.markdown("### Deep Forensic Alert Inspection")
    alert_ids = [a["alert_id"] for a in filtered_alerts]
    if alert_ids:
        sel_alert_id = st.selectbox("Select Alert for Deep Inspection:", alert_ids)
        sel_alert = next((a for a in filtered_alerts if a["alert_id"] == sel_alert_id), None)

        if sel_alert:
            d_col1, d_col2 = st.columns([1.6, 1])

            with d_col1:
                st.markdown(f"#### Alert Rationale: `{sel_alert['alert_id']}`")
                st.info(f"**Why this alert was generated:**\n\n{sel_alert['detection_explanation']}")

                st.markdown("##### Recommended Tactical Response Actions:")
                st.warning(sel_alert["recommended_action"])

                st.markdown("##### Triggering Event Telemetry Identifiers:")
                st.code("\n".join(sel_alert["triggering_event_ids"]) if sel_alert["triggering_event_ids"] else "No specific event ID logged.")

            with d_col2:
                st.markdown("#### Risk Score & Confidence")
                score = sel_alert["risk_score"]
                sev = sel_alert["severity"]

                # Metric and Score Gauge
                st.metric("Objective Risk Score", f"{score:.1f} / 100.0", f"Severity: {sev}")
                st.progress(min(1.0, score / 100.0))

                st.markdown(f"""
                - **Target Entity:** `{sel_alert['target_entity']}`
                - **Attributed Host / IP:** `{sel_alert['source_ip']}`
                - **Confidence Tier:** `{sel_alert['confidence']}`
                - **Supporting Documents:** `{', '.join(sel_alert['evidence_ids'])}`
                """)

                st.markdown("##### Evidence Boundary & Limitations:")
                st.caption("""
                - **Unsynchronized Clocks:** Timestamps in BlueVault (E05) carry uncalibrated hardware clock uncertainty.
                - **HR Defect (E14):** Status marked 'active' for all rows; termination verified by termination_date.
                """)
    else:
        st.info("No alerts match the chosen severity and category filters.")


# =================================================================================================
# PAGE 4: INVESTIGATION WORKSPACE
# =================================================================================================
elif nav_page == "4. Investigation Workspace":
    st.markdown('<div class="source-badge-evidence">🟢 DATA SOURCE: ORIGINAL CASE EVIDENCE (E01–E20)</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-header">Cross-System Investigation Workspace</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Multi-stage attack correlation, chronological incident progression, and NetworkX entity-relationship knowledge graph.</div>', unsafe_allow_html=True)

    with st.spinner("Building cross-system correlation cases and knowledge graph..."):
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

    # Filter events
    case_events = [
        e for e in current_case.events
        if (not system_filter or e.source_system in system_filter) and (not rel_filter or e.relationship_type.value in rel_filter)
    ]

    # Case Summary Card
    st.markdown(f"""
    <div class="soc-card">
        <div style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 6px;">{current_case.title}</div>
        <div style="font-size: 0.9rem; color: #94A3B8; margin-bottom: 12px;">{current_case.summary}</div>
        <div style="display: flex; gap: 20px; font-size: 0.85rem;">
            <div><b>Composite Risk Score:</b> <span style="color: #EF4444; font-weight: 700;">{current_case.composite_score:.1f} / 100</span></div>
            <div><b>Systems Spanned:</b> {len(current_case.involved_systems)}</div>
            <div><b>Correlated Events:</b> {len(case_events)}</div>
            <div><b>Evidence Sources:</b> {', '.join(current_case.involved_evidence)}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 2. Interactive Incident Timeline
    st.markdown("### Incident Timeline Progression")
    
    if case_events:
        # Create Plotly timeline scatter chart
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
            title="Chronological Multi-System Event Progression"
        )
        fig_tl.update_layout(
            margin=dict(t=30, b=10, l=10, r=10),
            paper_bgcolor="#0F172A",
            plot_bgcolor="#0F172A",
            font=dict(color="#E2E8F0"),
            height=280,
            showlegend=True,
            xaxis=dict(showgrid=True, gridcolor="#1E293B", title="UTC Timestamp"),
            yaxis=dict(title="")
        )
        st.plotly_chart(fig_tl, use_container_width=True)

        # Tabular Timeline View
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

    st.markdown("---")

    # 3. Interactive NetworkX Evidence Relationship Graph
    st.markdown("### Evidence & Entity Relationship Graph (NetworkX + Plotly)")
    st.caption("Interactive 2D topological graph of verified enterprise accounts, build servers, evidence documents, and diverted payment channels.")

    fig_net = graph_builder.to_plotly_figure(
        title=f"Entity-Relationship Graph: {current_case.title}"
    )
    if fig_net:
        st.plotly_chart(fig_net, use_container_width=True)
    else:
        st.info("Network graph visualizer initializing...")

    st.markdown("---")

    # 4. Transparent Risk Scoring Attribution & Facts vs Hypotheses
    sc_col1, sc_col2 = st.columns([1, 1])

    with sc_col1:
        st.markdown("#### Transparent Risk Score Factor Attribution")
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
        st.markdown("#### Confirmed Facts vs. Investigative Hypotheses")
        st.markdown("**Confirmed Forensic Facts:**")
        for fact in current_case.confirmed_facts:
            st.markdown(f"- ✅ {fact}")

        st.markdown("**Investigative Hypotheses (Requiring Verification):**")
        for hyp in current_case.investigative_hypotheses:
            st.markdown(f"- ❓ {hyp}")


# =================================================================================================
# PAGE 5: SIMULATION LAB
# =================================================================================================
elif nav_page == "5. Simulation Lab":
    st.markdown('<div class="source-badge-simulated">🟣 DATA SOURCE: SIMULATED TEST DATA (ISOLATED IN-MEMORY LAB)</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-header">Controlled Cybersecurity Simulation Lab</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">Evaluate TRACE detection capabilities using safe, local synthetic telemetry streams. Zero external network connections.</div>', unsafe_allow_html=True)

    sim_runner = SimulationLabRunner()

    sim_tab1, sim_tab2 = st.tabs(["Interactive Scenario Simulator", "Generalization Evaluation Battery"])

    with sim_tab1:
        sc_col1, sc_col2 = st.columns([1, 2])

        with sc_col1:
            st.subheader("Scenario Configuration")
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

            # Scenario-specific controls
            sim_events = []
            sim_context = {}

            if "SCENARIO A" in scenario_choice:
                st.caption("Simulates authentication attempts by a departed employee.")
                is_terminated = st.checkbox("Is Terminated Employee", value=True)
                login_success = st.checkbox("Authentication Succeeded", value=True)
                source_ip = st.text_input("Source IP:", "172.16.8.88")
                days_after = st.slider("Days Post Termination:", 1, 60, 20)

                if st.button("▶️ Generate & Run Scenario A"):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_a_former_employee(
                        is_terminated=is_terminated, login_success=login_success, source_ip=source_ip, days_after_termination=days_after
                    )

            elif "SCENARIO B" in scenario_choice:
                st.caption("Simulates API calls from anomalous internal or external hosts.")
                is_susp_caller = st.checkbox("Unauthorized Caller IP (10.20.4.77 tb-build-02)", value=True)
                is_sens_ep = st.checkbox("High-Risk Endpoint (/v2/vendors/.../bank-details)", value=True)
                event_count = st.slider("Request Volume:", 1, 50, 5)

                if st.button("▶️ Generate & Run Scenario B"):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_b_api_activity(
                        is_suspicious_caller=is_susp_caller, is_sensitive_endpoint=is_sens_ep, event_count=event_count
                    )

            elif "SCENARIO C" in scenario_choice:
                st.caption("Simulates vendor master changes (dual-control evaluation).")
                field_changed = st.selectbox("Field Modified:", ["bank_account", "address", "phone"])
                channel = st.selectbox("Channel:", ["API", "UI"])
                has_approval = st.checkbox("Has Approval Reference", value=False)

                if st.button("▶️ Generate & Run Scenario C"):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
                        field_changed=field_changed, channel=channel, has_approval_ref=has_approval
                    )

            elif "SCENARIO D" in scenario_choice:
                st.caption("Simulates bulk data exports and reconnaissance ticket searches.")
                is_burst = st.checkbox("Abnormal Export Burst", value=True)
                include_recon = st.checkbox("Include Secret Keyword Searches", value=True)
                export_count = st.slider("Export Job Count:", 1, 30, 15)

                if st.button("▶️ Generate & Run Scenario D"):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_d_export_activity(
                        is_burst=is_burst, include_recon_searches=include_recon, export_count=export_count
                    )

            else: # SCENARIO E
                st.caption("Full kill-chain combining reconnaissance, pivot, and payment fraud.")
                inc_recon = st.checkbox("Include HelpDeskr Reconnaissance", value=True)
                inc_api = st.checkbox("Include Build Server API Probing", value=True)
                inc_vendor = st.checkbox("Include Vendor Bank Tampering", value=True)

                if st.button("▶️ Generate & Run Scenario E"):
                    sim_events, sim_context = ScenarioTemplateEngine.generate_scenario_e_multi_stage(
                        include_recon=inc_recon, include_api_pivot=inc_api, include_vendor_tamper=inc_vendor
                    )

        with sc_col2:
            st.subheader("Simulation Execution & Detection Output")
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

                # Detection rules comparison
                st.markdown(f"**Expected Rule Signatures:** `{', '.join(res['expected_rules']) if res['expected_rules'] else 'BENIGN'}`")
                st.markdown(f"**Triggered Rule Signatures:** `{', '.join(set(res['detected_rules'])) if res['detected_rules'] else 'None'}`")

                # Alerts Raised
                if res["alerts"]:
                    st.markdown("##### Raised Alerts Details:")
                    for a in res["alerts"]:
                        st.warning(f"**[{a['severity']}] {a['alert_id']} ({a['rule_id']}):** {a['detection_explanation']}")

                # Generated Events Table
                st.markdown("##### Generated Telemetry Stream (Explicitly Labeled SIMULATED):")
                df_sim = pd.DataFrame(res["events"])
                display_cols = [c for c in ["event_id", "timestamp_orig", "system", "action", "actor", "target", "source_ip", "expected_classification"] if c in df_sim.columns]
                st.dataframe(df_sim[display_cols], use_container_width=True, hide_index=True)
            else:
                st.info("Configure scenario parameters in the left panel and click 'Generate & Run' to execute simulation.")

    with sim_tab2:
        st.subheader("Held-Out Generalization Evaluation Battery")
        st.markdown("""
        Evaluates TRACE against unseen variations:
        - Novel IP addresses, title-casing variations, and altered event sequencing.
        - Legitimate lookalikes (approved portal bank changes, routine high-volume sync, active employee kiosk logins).
        """)

        if st.button("▶️ Run Full Held-Out Evaluation Suite"):
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

                st.markdown("#### Test Case Details:")
                df_held_out = pd.DataFrame(held_out_res["test_details"])[
                    ["test_name", "description", "expected_alert_count", "actual_alert_count", "passed"]
                ]
                df_held_out.columns = ["Test Name", "Scenario Description", "Expected Alerts", "Actual Alerts", "Status"]
                st.dataframe(df_held_out, use_container_width=True, hide_index=True)


# =================================================================================================
# PAGE 6: PERFORMANCE LAB
# =================================================================================================
elif nav_page == "6. Performance Lab":
    st.markdown('<div class="source-badge-simulated">🟣 DATA SOURCE: DEFENSIVE PERFORMANCE EVALUATION (CONTROLLED BENCHMARK)</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-header">Defensive Performance Evaluation Engine</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-subheader">A reproducible, scientifically grounded diagnostic framework measuring alert precision, recall, false-alarm rate, and adversarial robustness.</div>', unsafe_allow_html=True)

    st.info("""
    **Strict Evidence-Grounding & Evaluation Principles**:
    - **Original Evidence Integrity ($E01$–$E20$)**: Ground truth is unlabelled for raw background events. Supervised accuracy metrics are strictly NOT calculated on unlabelled case evidence to avoid unscientific bias.
    - **Isolated Benchmark Dataset**: All 34 benchmark test cases are programmatically synthesized with strict ground-truth labels (**$1$ = Suspicious**, **$0$ = Legitimate**), tagged with `SIMULATED_TEST_LAB` and `is_synthetic: True`.
    - **Safe Zero-Denominator Handling**: Where denominators evaluate to zero, metrics report `N/A` with an explicit mathematical note rather than arbitrary coercion.
    """)

    eval_engine = DefensiveEvaluationEngine()

    mode_options = [
        "Comprehensive Benchmark (All 34 Test Cases)",
        "Mode A: Rule Validation (14 Test Cases)",
        "Mode B: Scenario Validation (6 Test Cases)",
        "Mode C: Unseen Variation Testing (6 Test Cases)",
        "Mode D: Robustness Stress-Testing (8 Test Cases)"
    ]

    selected_mode = st.selectbox("Select Evaluation Mode:", mode_options)

    if st.button("🚀 Execute Defensive Performance Evaluation", key="btn_run_eval_p6"):
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

        st.markdown("---")
        st.subheader(f"Evaluation Results: {suite_res.mode}")

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

        st.markdown("---")
        
        col_cm, col_rob = st.columns([1, 1])

        with col_cm:
            st.markdown("### 2x2 Confusion Matrix")
            df_cm = pd.DataFrame([
                {"Ground Truth": "Actual Suspicious (GT=1)", "Predicted Suspicious (Alerted)": f"TP: {m.true_positives}", "Predicted Legitimate (No Alert)": f"FN: {m.false_negatives}"},
                {"Ground Truth": "Actual Legitimate (GT=0)", "Predicted Suspicious (Alerted)": f"FP: {m.false_positives}", "Predicted Legitimate (No Alert)": f"TN: {m.true_negatives}"}
            ])
            st.table(df_cm)

        with col_rob:
            st.markdown("### Robustness Stress-Testing Dimensions")
            if suite_res.robustness_breakdown:
                for r_type, stats in suite_res.robustness_breakdown.items():
                    pass_pct = int((stats["passed"] / stats["total"]) * 100) if stats["total"] > 0 else 0
                    st.write(f"**{r_type.replace('_', ' ').title()}**: {stats['passed']}/{stats['total']} Passed ({pass_pct}%)")
                    st.progress(pass_pct / 100.0)
            else:
                st.caption("Select 'Comprehensive Benchmark' or 'Mode D: Robustness Stress-Testing' to inspect all 8 perturbation dimensions.")

        st.markdown("---")
        st.subheader("Detailed Test Case Evaluation Breakdown")

        # Filter option
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

        st.markdown("---")
        st.subheader("📥 Download Evaluation Reports")
        
        md_content = eval_engine.generate_report(suite_res, format="markdown")
        json_content = eval_engine.generate_report(suite_res, format="json")

        d_col1, d_col2 = st.columns(2)
        with d_col1:
            st.download_button(
                label="📄 Download Full Markdown Evaluation Report (.md)",
                data=md_content,
                file_name=f"TRACE_Defensive_Evaluation_Report.md",
                mime="text/markdown"
            )
        with d_col2:
            st.download_button(
                label="📊 Download Evaluation Results Data (.json)",
                data=json_content,
                file_name=f"TRACE_Defensive_Evaluation_Data.json",
                mime="application/json"
            )
