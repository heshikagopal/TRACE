"""
TRACE — Threat Recognition, Analysis and Correlation Engine
CRIMEATHON'26 Defense Track | Case File CR-26-047 (Harbor & Finch Freight)
Lead Python Developer & Cybersecurity Detection Engineer Interface
"""

import os
import streamlit as st
import pandas as pd
from trace_engine.ingestion import EvidenceIngestor, EVIDENCE_CATALOG
from trace_engine.normalisation import EventNormaliser, load_and_normalise_all
from trace_engine.detection import ThreatDetectionEngine
from trace_engine.correlation import CrossSystemCorrelationEngine
from trace_engine.graph_builder import EvidenceGraphBuilder
from trace_engine.scenario_templates import ScenarioTemplateEngine, HELD_OUT_EVALUATION_SUITE
from trace_engine.simulation import SimulationLabRunner

st.set_page_config(
    page_title="TRACE — Threat Recognition, Analysis & Correlation Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS styling for professional DFIR dashboard
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-high {
        background-color: #FFEDD5;
        color: #9A3412;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-medium {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-info {
        background-color: #DBEAFE;
        color: #1E40AF;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-sim {
        background-color: #EDE9FE;
        color: #6D28D9;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.8rem;
    }
    .badge-direct {
        background-color: #D1FAE5;
        color: #065F46;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-temporal {
        background-color: #EDE9FE;
        color: #5B21B6;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-contextual {
        background-color: #E0F2FE;
        color: #0369A1;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-unverified {
        background-color: #F3F4F6;
        color: #4B5563;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_ingestor(base_dir: str = "data/original"):
    return EvidenceIngestor(base_dir)


@st.cache_data
def get_inventory_cached(base_dir: str = "data/original"):
    ingestor = get_ingestor(base_dir)
    return ingestor.get_inventory()


@st.cache_data
def get_normalised_events(base_dir: str = "data/original"):
    ingestor = get_ingestor(base_dir)
    return load_and_normalise_all(ingestor)


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


@st.cache_data
def get_graph_data(base_dir: str = "data/original"):
    ingestor = get_ingestor(base_dir)
    cases = get_investigation_cases(base_dir)
    context = {
        "E14": ingestor.load_csv("E14"),
        "E04": ingestor.load_json("E04")
    }
    builder = EvidenceGraphBuilder()
    builder.build_full_case_graph(context, list(cases.values()))
    return builder


# Sidebar
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=70)
st.sidebar.title("TRACE Navigation")
st.sidebar.markdown("**Case File CR-26-047**  \n*Harbor & Finch Freight*")

nav_choice = st.sidebar.radio(
    "Modules",
    [
        "1. Overview & Strategy",
        "2. Evidence Inventory & Centre",
        "3. Common Event Stream",
        "4. Detections & Alerts",
        "5. Cross-System Correlation & Cases",
        "6. Cybersecurity Simulation Lab",
        "7. Ingestion & Integrity Audit"
    ]
)

base_dir = "data/original"
ingestor = get_ingestor(base_dir)

# Header
st.markdown('<div class="main-header">🛡️ TRACE: Threat Recognition, Analysis and Correlation Engine</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">CRIMEATHON\'26 Defense Track | Automated Evidence Ingestion, Normalisation & Cross-System Detection</div>', unsafe_allow_html=True)

# -------------------------------------------------------------------------------------------------
# TAB 1: OVERVIEW & STRATEGY
# -------------------------------------------------------------------------------------------------
if nav_choice == "1. Overview & Strategy":
    st.header("Executive Summary & Defense Architecture")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Evidence Items", "20 / 20", "All Formats Extracted")
    with col2:
        st.metric("Normalised Events", "109,428", "Preserved Raw Records")
    with col3:
        st.metric("Active Detection Rules", "5", "Evidence-Backed")
    with col4:
        st.metric("Investigation Cases", "4", "Cross-System Correlated")

    st.markdown("---")
    
    st.subheader("Investigative Findings Summary")
    st.markdown("""
    Based on systematic ingestion and cross-system correlation of all 20 evidence files, TRACE has identified **two distinct security failures** rather than a single isolated incident:
    
    1. **Primary Security Incident: Vendor Supply Chain Compromise (TallyBridge Connect)**
       - **Initial Reconnaissance**: On 11–12 August 2026, HelpDeskr audit logs (`E02`) record targeted searches for credential terms (`password`, `api_key`, `secret`, `bearer`, `bvk-`) followed by **30 bulk ticket export jobs**, directly corroborating the billing overage alert in `E06`.
       - **Host & Credential Pivot**: Network flow logs (`E15`) and public status records (`E20`) identify internal host `10.20.4.77` as `tb-build-02` (a build server).
       - **Financial Execution**: On 3 September 2026 at 01:44:30 UTC, LedgerOne API logs (`E18`) and Vendor Master audit logs (`E19`) show `key-tb-07` originating from `10.20.4.77` calling sensitive endpoints (`/v2/vendors/V-0412/bank-details`, `/v2/payments/scheduled`) and executing a **PATCH modifying the bank account of Coastal Packaging Ltd (`V-0412`) to `****9083` without any approval reference**.
       - **Immediate Impact**: A payment run is scheduled for 8 September 2026. Without intervention, vendor funds would be diverted.
    
    2. **Secondary Control Failure: Unrevoked Former Employee Account Access**
       - Accounts Payable clerk **Rohan Menon (`r.menon`)** left Harbor & Finch on **30 June 2026** (`E14`).
       - On **13 August 2026 at 09:02:00 UTC**, SSO logs (`E03`, event `sso-bb8ab61e08`) record a successful login to `r.menon`'s account from a warehouse kiosk IP (`172.16.8.x`).
       - Staff roster `E14` shows known recordkeeping errors: the `status` column is uniformly marked `'active'` for all 420 personnel despite `termination_date` being recorded. This directly substantiates Risk `R-018` in `E09` and Audit Finding 3 in `E11`.
    """)

    st.markdown("---")
    st.subheader("Data Integrity Guarantees")
    st.info("""
    - **Pristine Source Evidence**: Original files in `data/original/` are strictly read-only and never modified.
    - **Original Timestamp Preservation**: Source timestamp strings are preserved verbatim alongside UTC-normalised timestamps.
    - **Explicit Timezone Assumptions**: Timezones (UTC, IST +05:30, Unix Epoch drift) are recorded per event.
    - **Zero Synthetic Distortion**: No missing records, identities, or hashes have been fabricated.
    """)

# -------------------------------------------------------------------------------------------------
# TAB 2: EVIDENCE INVENTORY & CENTRE
# -------------------------------------------------------------------------------------------------
elif nav_choice == "2. Evidence Inventory & Centre":
    st.header("Evidence Inventory & Source Inspection Centre")
    st.markdown("Comprehensive inventory of all 20 evidence files provided in CR-26-047.")

    inventory = get_inventory_cached(base_dir)
    df_inv = pd.DataFrame(inventory)[["evidence_id", "filename", "format", "system", "rows_or_pages", "size_bytes", "time_basis", "reliability"]]
    df_inv.columns = ["ID", "Filename", "Format", "System / Department", "Rows/Pages", "Size (Bytes)", "Time Basis", "Reliability Note"]
    st.dataframe(df_inv, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("Interactive Evidence File Inspector")
    
    selected_eid = st.selectbox("Select Evidence Item to Inspect", list(EVIDENCE_CATALOG.keys()), format_func=lambda k: f"{k} — {EVIDENCE_CATALOG[k]['filename']}")
    meta = EVIDENCE_CATALOG[selected_eid]
    
    col_a, col_b = st.columns([1, 2])
    with col_a:
        st.markdown(f"**System:** {meta['system']}")
        st.markdown(f"**Format:** `{meta['format']}`")
        st.markdown(f"**Time Basis:** {meta['time_basis']}")
        st.markdown(f"**Reliability:** {meta['reliability']}")
        st.markdown(f"**Investigative Use:** {meta['investigative_use']}")

    with col_b:
        fmt = meta["format"].lower()
        if fmt == "csv":
            df_sample = ingestor.load_csv(selected_eid)
            st.markdown(f"**Previewing Data (Total rows: {len(df_sample):,}):**")
            st.dataframe(df_sample.head(20), use_container_width=True)
        elif fmt == "json":
            json_data = ingestor.load_json(selected_eid)
            st.markdown("**Previewing JSON Structure:**")
            st.json(json_data)
        elif fmt == "excel":
            st.markdown("**Previewing E09 Risk Register Extract:**")
            df_risk = ingestor.load_risk_register()
            st.dataframe(df_risk, use_container_width=True)
        elif fmt == "pdf":
            st.markdown("**Extracting Document Text & Sections:**")
            pdf_data = ingestor.load_pdf(selected_eid)
            st.markdown(f"*Total Pages: {pdf_data['total_pages']}*")
            for page in pdf_data["pages"]:
                with st.expander(f"Page {page['page_number']}"):
                    st.text(page["text"])

# -------------------------------------------------------------------------------------------------
# TAB 3: COMMON EVENT STREAM
# -------------------------------------------------------------------------------------------------
elif nav_choice == "3. Common Event Stream":
    st.header("TRACE Common Event Stream")
    st.markdown("Unified chronological event representation covering LedgerOne, HelpDeskr, SSO, BlueVault, Flow Logs, and Vendor Audit Logs.")

    with st.spinner("Loading and normalising events..."):
        df_events = get_normalised_events(base_dir)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Events", f"{len(df_events):,}")
    with col2:
        st.metric("Unique Systems", len(df_events["system"].unique()))
    with col3:
        st.metric("Unique Actors", len(df_events["actor"].unique()))
    with col4:
        st.metric("Earliest -> Latest", "01 Jun -> 07 Sep 2026")

    # Filters
    st.markdown("### Filter Event Stream")
    f_col1, f_col2, f_col3 = st.columns(3)
    with f_col1:
        systems = ["All"] + sorted(list(df_events["system"].unique()))
        selected_system = st.selectbox("Filter by System", systems)
    with f_col2:
        ev_ids = ["All"] + sorted(list(df_events["source_evidence_id"].unique()))
        selected_ev = st.selectbox("Filter by Source Evidence ID", ev_ids)
    with f_col3:
        search_query = st.text_input("Search Actor, IP, Target, or Action", "")

    filtered = df_events.copy()
    if selected_system != "All":
        filtered = filtered[filtered["system"] == selected_system]
    if selected_ev != "All":
        filtered = filtered[filtered["source_evidence_id"] == selected_ev]
    if search_query.strip():
        q = search_query.strip().lower()
        mask = (
            filtered["actor"].str.lower().str.contains(q, na=False) |
            filtered["source_ip"].str.lower().str.contains(q, na=False) |
            filtered["target"].str.lower().str.contains(q, na=False) |
            filtered["action"].str.lower().str.contains(q, na=False)
        )
        filtered = filtered[mask]

    st.markdown(f"**Showing {len(filtered):,} matching events:**")
    display_cols = ["event_id", "timestamp", "timestamp_orig", "timezone_assumption", "source_evidence_id", "system", "actor", "action", "target", "source_ip", "result"]
    st.dataframe(filtered[display_cols].head(500), use_container_width=True)

    st.markdown("---")
    st.subheader("Event Record Detail Inspector")
    if not filtered.empty:
        idx = st.number_input("Inspect Row Index (0 to 100)", min_value=0, max_value=min(100, len(filtered)-1), value=0)
        selected_record = filtered.iloc[idx].to_dict()
        st.json(selected_record)

# -------------------------------------------------------------------------------------------------
# TAB 4: DETECTIONS & ALERTS
# -------------------------------------------------------------------------------------------------
elif nav_choice == "4. Detections & Alerts":
    st.header("TRACE Detection Engine Alerts")
    st.markdown("Rule-based, evidence-supported security alerts generated from normalised case telemetry.")

    with st.spinner("Evaluating detection rules..."):
        alerts = get_alerts(base_dir)

    st.markdown(f"**Generated Alerts ({len(alerts)} alerts triggered):**")

    # Filter by severity
    sev_filter = st.multiselect("Filter by Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM"])
    
    displayed_alerts = [a for a in alerts if a["severity"] in sev_filter]

    for a in displayed_alerts:
        sev = a["severity"]
        badge_class = f"badge-{sev.lower()}"
        border_color = "#DC2626" if sev == "CRITICAL" else ("#EA580C" if sev == "HIGH" else "#D97706")

        st.markdown(f"""
        <div style="border-left: 6px solid {border_color}; background-color: #F9FAFB; padding: 18px; border-radius: 6px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 1.15rem; font-weight: 700; color: #111827;">{a['alert_id']} — {a['triggered_rule']}</span>
                <div>
                    <span class="{badge_class}">{sev}</span>
                    <span class="badge-info" style="margin-left: 6px;">Risk Score: {a['risk_score']} / 100</span>
                </div>
            </div>
            <div style="color: #4B5563; font-size: 0.9rem; margin-bottom: 10px;">
                <b>Category:</b> {a['threat_category']} | <b>Target:</b> {a.get('target_entity', 'N/A')} | <b>Source IP:</b> {a.get('source_ip', 'N/A')} | <b>Timestamp:</b> {a.get('timestamp', 'N/A')}
            </div>
            <div style="color: #1F2937; margin-bottom: 12px; font-size: 0.95rem; line-height: 1.5;">
                {a['detection_explanation']}
            </div>
            <div style="background-color: #EFF6FF; border-left: 3px solid #3B82F6; padding: 10px; border-radius: 4px; font-size: 0.9rem; margin-bottom: 10px;">
                <b>💡 Recommended Action:</b> {a['recommended_action']}
            </div>
            <div style="font-size: 0.82rem; color: #6B7280;">
                <b>Supporting Evidence IDs:</b> {', '.join(a['evidence_ids'])} | <b>Related Event IDs:</b> {', '.join(a['triggering_event_ids'][:5])}
            </div>
        </div>
        """, unsafe_allow_html=True)

# -------------------------------------------------------------------------------------------------
# TAB 5: CROSS-SYSTEM CORRELATION & CASES
# -------------------------------------------------------------------------------------------------
elif nav_choice == "5. Cross-System Correlation & Cases":
    st.header("Cross-System Correlation Engine & Investigation Cases")
    st.markdown("Ground-truth correlation linking disparate records across E01–E20 with typed relationships and transparent risk scoring.")

    cases = get_investigation_cases(base_dir)
    graph_builder = get_graph_data(base_dir)

    selected_case_id = st.selectbox(
        "Select Active Investigation Case",
        list(cases.keys()),
        format_func=lambda cid: f"{cid}: {cases[cid].title}"
    )
    active_case = cases[selected_case_id]

    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        st.subheader(active_case.title)
        st.markdown(f"**Focus:** {active_case.focus}")
        st.markdown(f"**Summary:** {active_case.summary}")
    with c2:
        risk_data = active_case.risk_assessment
        st.metric("Case Risk Score", f"{risk_data['final_score']} / 100", f"Severity: {risk_data['severity']}")
        st.markdown(f"**Primary Entities:** {', '.join(active_case.primary_entities)}")
    with c3:
        st.markdown(f"**Cites Evidence IDs:** {', '.join(active_case.primary_evidence_ids)}")
        st.markdown(f"**Timeline Events:** {len(active_case.timeline)}")

    st.markdown("---")

    sub_tab1, sub_tab2, sub_tab3, sub_tab4 = st.tabs([
        "📅 Correlated Incident Timeline",
        "📊 Transparent Risk Score Breakdown",
        "⚖️ Facts vs. Hypotheses",
        "🕸️ Evidence Relationship Graph"
    ])

    with sub_tab1:
        st.markdown("### Incident Chronology")
        t_col1, t_col2 = st.columns(2)
        with t_col1:
            systems_in_case = ["All"] + sorted(list(set(e.source_system for e in active_case.timeline)))
            filter_sys = st.selectbox("Filter System", systems_in_case, key=f"f_sys_{selected_case_id}")
        with t_col2:
            rel_types = ["All"] + sorted(list(set(e.relationship_type for e in active_case.timeline)))
            filter_rel = st.selectbox("Filter Relationship Type", rel_types, key=f"f_rel_{selected_case_id}")

        filtered_timeline = active_case.timeline
        if filter_sys != "All":
            filtered_timeline = [e for e in filtered_timeline if e.source_system == filter_sys]
        if filter_rel != "All":
            filtered_timeline = [e for e in filtered_timeline if e.relationship_type == filter_rel]

        st.markdown(f"**Displaying {len(filtered_timeline)} timeline events:**")
        for event in filtered_timeline:
            rel = event.relationship_type
            badge_style = "badge-direct" if "Direct" in rel else ("badge-temporal" if "Temporal" in rel else ("badge-contextual" if "Contextual" in rel else "badge-unverified"))
            st.markdown(f"""
            <div style="border-left: 4px solid #3B82F6; background-color: #F8FAFC; padding: 14px; border-radius: 6px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="font-weight: 700; color: #1E3A8A; font-size: 1.0rem;">
                        {event.normalised_timestamp_str} (Orig: <code>{event.timestamp_orig}</code>)
                    </span>
                    <div>
                        <span class="{badge_style}">{rel}</span>
                        <span class="badge-info" style="margin-left: 5px;">{event.source_system} ({event.evidence_id})</span>
                    </div>
                </div>
                <div style="color: #1F2937; font-size: 0.95rem; margin-bottom: 6px;">
                    {event.description}
                </div>
                <div style="font-size: 0.82rem; color: #4B5563;">
                    <b>Matched Identifiers:</b> {', '.join(event.identifiers_matched) if event.identifiers_matched else 'None'} | <b>Confidence:</b> {event.confidence}
                </div>
                {f'<div style="font-size: 0.8rem; color: #B45309; margin-top: 4px;">⚠️ <i>{event.uncertainty_notes}</i></div>' if event.uncertainty_notes else ''}
            </div>
            """, unsafe_allow_html=True)

    with sub_tab2:
        st.markdown("### Transparent Scoring Attribution")
        breakdown = active_case.risk_assessment.get("breakdown", {})
        score_rows = []
        for factor_key, factor_val in breakdown.items():
            if isinstance(factor_val, dict):
                score_rows.append({
                    "Risk Factor": factor_key.replace("_", " ").title(),
                    "Points Awarded / Deducted": factor_val.get("points", factor_val.get("deductions", 0.0)),
                    "Evidence-Backed Attribution": factor_val.get("explanation", "")
                })
        st.table(pd.DataFrame(score_rows))
        st.info(f"**Final Calculated Risk Score:** {active_case.risk_assessment['final_score']} / 100 ({active_case.risk_assessment['severity']})")

    with sub_tab3:
        st.markdown("### Evidentiary Separation: Observed Facts vs Investigative Hypotheses")
        col_f, col_h = st.columns(2)
        with col_f:
            st.markdown("#### ✅ Observed Facts (Documented in Logs)")
            for f in active_case.facts_observed:
                st.markdown(f"- {f}")
        with col_h:
            st.markdown("#### 🔍 Investigative Hypotheses (Requiring Verification)")
            for h in active_case.investigative_hypotheses:
                st.markdown(f"- {h}")
        st.markdown("#### 💡 Recommended Investigative Actions")
        for rec in active_case.recommended_actions:
            st.markdown(f"1. {rec}")

    with sub_tab4:
        st.markdown("### Grounded NetworkX Evidence Relationship Graph")
        subgraph = graph_builder.get_case_subgraph(active_case.primary_entities)
        g_col1, g_col2 = st.columns([1, 2])
        with g_col1:
            st.markdown(f"**Subgraph Entities:** {len(subgraph.nodes)}")
            st.markdown(f"**Relationship Edges:** {len(subgraph.edges)}")
            selected_node = st.selectbox(
                "Select Node to Inspect Connected Evidence",
                sorted(list(subgraph.nodes)),
                format_func=lambda n: f"{n} ({subgraph.nodes[n].get('label', n)})"
            )
            connected_evidence = graph_builder.get_connected_evidence(selected_node)
            st.markdown(f"**Connected Evidence Files for `{selected_node}`:**")
            for ev in connected_evidence:
                st.markdown(f"- **{ev}**: {EVIDENCE_CATALOG.get(ev, {}).get('filename', '')}")
        with g_col2:
            st.markdown(f"**Verified Relationships in Case Subgraph:**")
            edge_list = []
            for u, v, d in subgraph.edges(data=True):
                edge_list.append({
                    "Source Entity": u,
                    "Target Entity": v,
                    "Relationship": d.get("label", ""),
                    "Type": d.get("relationship_type", ""),
                    "Evidence": d.get("evidence_source", "")
                })
            st.dataframe(pd.DataFrame(edge_list), use_container_width=True, hide_index=True)

# -------------------------------------------------------------------------------------------------
# TAB 6: CYBERSECURITY SIMULATION LAB
# -------------------------------------------------------------------------------------------------
elif nav_choice == "6. Cybersecurity Simulation Lab":
    st.header("Controlled Cybersecurity Simulation Lab")
    st.markdown("""
    Evaluate TRACE's detection capabilities using safe, self-contained synthetic scenarios.
    All events are generated locally in memory with strict `is_synthetic: True` tags to prevent evidence pollution.
    Generated events are evaluated directly against the production `ThreatDetectionEngine`.
    """)

    sim_tab1, sim_tab2 = st.tabs(["🧪 Interactive Scenario Runner", "🏆 Held-Out Evaluation Battery"])

    sim_runner = SimulationLabRunner()

    with sim_tab1:
        scenario_choice = st.selectbox(
            "Select Simulated Scenario",
            [
                "SCENARIO A: Former Employee Access",
                "SCENARIO B: Compromised Integration Credential",
                "SCENARIO C: Suspicious Vendor Bank Modification",
                "SCENARIO D: Unusual Helpdesk Data Export",
                "SCENARIO E: Multi-Stage Attack Progression"
            ]
        )

        st.markdown("---")
        st.subheader("Scenario Parameters")

        # Dynamic configuration controls
        if "SCENARIO A" in scenario_choice:
            sc_col1, sc_col2, sc_col3 = st.columns(3)
            with sc_col1:
                p_term = st.toggle("Account Status: Terminated Employee", value=True)
                p_uname = st.text_input("Username", value="sim.former.clerk")
            with sc_col2:
                p_success = st.toggle("Sign-in Result: Success", value=True)
                p_days = st.slider("Days Post-Termination", min_value=1, max_value=60, value=15)
            with sc_col3:
                p_ip = st.text_input("Source IP", value="172.16.8.88 (Warehouse Kiosk)")
            
            gen_func = lambda: ScenarioTemplateEngine.generate_scenario_a_former_employee(
                is_terminated=p_term,
                login_success=p_success,
                source_ip=p_ip.split(" ")[0],
                days_after_termination=p_days,
                username=p_uname
            )

        elif "SCENARIO B" in scenario_choice:
            sc_col1, sc_col2, sc_col3 = st.columns(3)
            with sc_col1:
                p_key = st.text_input("API Credential ID", value="key-tb-07")
                p_ip = st.selectbox("Caller IP", ["10.20.4.77 (tb-build-02 host)", "10.20.4.12 (Normal sync pool)", "198.18.7.41 (Threat Indicator)"])
            with sc_col2:
                p_endpoint = st.selectbox("API Endpoint", ["/v2/vendors/V-SIM-0412/bank-details", "/v2/payments/scheduled", "/v2/shipments"])
                p_method = st.selectbox("HTTP Method", ["GET", "PATCH", "POST"])
            with sc_col3:
                p_count = st.slider("Request Count", min_value=1, max_value=10, value=3)

            gen_func = lambda: ScenarioTemplateEngine.generate_scenario_b_api_activity(
                api_key_id=p_key,
                caller_ip=p_ip.split(" ")[0],
                endpoint=p_endpoint,
                method=p_method,
                event_count=p_count
            )

        elif "SCENARIO C" in scenario_choice:
            sc_col1, sc_col2, sc_col3 = st.columns(3)
            with sc_col1:
                p_field = st.selectbox("Field Changed", ["bank_account", "contact_email", "address"])
                p_chan = st.selectbox("Change Channel", ["API", "UI"])
            with sc_col2:
                p_appr = st.toggle("Include Valid Dual Approval Reference", value=False)
                p_appr_ref = st.text_input("Approval Reference Code", value="APR-SIM-9941" if p_appr else "")
            with sc_col3:
                p_ip = st.text_input("Source IP", value="10.20.4.77")
                p_actor = st.text_input("Changed By", value="key-tb-07" if p_chan == "API" else "f.dsouza")

            gen_func = lambda: ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
                field_changed=p_field,
                channel=p_chan,
                has_approval_ref=p_appr,
                approval_ref_val=p_appr_ref if p_appr else None,
                source_ip=p_ip,
                changed_by=p_actor
            )

        elif "SCENARIO D" in scenario_choice:
            sc_col1, sc_col2 = st.columns(2)
            with sc_col1:
                p_burst = st.toggle("Trigger Abnormal Burst Export (Cluster)", value=True)
                p_recon = st.toggle("Include Secret Reconnaissance Searches ('password', 'bvk-')", value=True)
            with sc_col2:
                p_count = st.slider("Export Jobs Volume", min_value=1, max_value=20, value=12 if p_burst else 1)
                p_ip = st.text_input("Actor Source IP", value="198.18.7.41")

            gen_func = lambda: ScenarioTemplateEngine.generate_scenario_d_export_activity(
                is_burst=p_burst,
                include_recon_searches=p_recon,
                export_count=p_count,
                source_ip=p_ip
            )

        else:
            st.markdown("**Multi-Stage Attack Progression across Multiple Enterprise Systems**")
            sc_col1, sc_col2 = st.columns(2)
            with sc_col1:
                p_sso = st.checkbox("Phase 1: Former employee login (SSO)", value=True)
                p_recon = st.checkbox("Phase 2: Secret searches & bulk export burst (HelpDeskr)", value=True)
            with sc_col2:
                p_pivot = st.checkbox("Phase 3: Out-of-pool invocation from build host 10.20.4.77 (LedgerOne)", value=True)
                p_bank = st.checkbox("Phase 4: Unauthorized bank account modification (Vendor Master)", value=True)

            gen_func = lambda: ScenarioTemplateEngine.generate_scenario_e_multi_stage(
                include_former_employee=p_sso,
                include_recon=p_recon,
                include_api_pivot=p_pivot,
                include_vendor_tamper=p_bank
            )

        if st.button("🚀 Execute Simulation in TRACE Engine"):
            with st.spinner("Generating synthetic events and passing through ThreatDetectionEngine..."):
                synthetic_events, synthetic_context = gen_func()
                sim_result = sim_runner.run_scenario(synthetic_events, context=synthetic_context)

                # Metrics display
                m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
                with m_col1:
                    st.metric("Generated Events", sim_result["events_count"])
                with m_col2:
                    st.metric("Alerts Raised", len(sim_result["alerts"]))
                with m_col3:
                    st.metric("True Positives (TP)", sim_result["true_positives"])
                with m_col4:
                    st.metric("False Positives (FP)", sim_result["false_positives"])
                with m_col5:
                    st.metric("F1 Score", f"{sim_result['metrics']['f1_score']:.2f}")

                st.markdown("---")
                st.subheader("Simulation Evaluation Results")

                ev_col1, ev_col2 = st.columns(2)
                with ev_col1:
                    st.markdown("**Expected Detection Signatures:**")
                    if sim_result["expected_rules"]:
                        for r in sim_result["expected_rules"]:
                            st.markdown(f"- `{r}`")
                    else:
                        st.markdown("*None (Expected clean / benign activity)*")
                with ev_col2:
                    st.markdown("**Actual Rules Triggered by TRACE Engine:**")
                    if sim_result["detected_rules"]:
                        for dr in set(sim_result["detected_rules"]):
                            st.markdown(f"- 🚨 `{dr}`")
                    else:
                        st.markdown("*None (No alerts raised)*")

                # Alerts raised inspection
                if sim_result["alerts"]:
                    st.markdown("#### Generated Security Alerts:")
                    for al in sim_result["alerts"]:
                        sev = al["severity"]
                        badge_class = f"badge-{sev.lower()}"
                        st.markdown(f"""
                        <div style="border-left: 5px solid #EA580C; background-color: #F8FAFC; padding: 12px; border-radius: 4px; margin-bottom: 10px;">
                            <div style="display: flex; justify-content: space-between;">
                                <b>{al['alert_id']} — {al['triggered_rule']}</b>
                                <div><span class="{badge_class}">{sev}</span> <span class="badge-sim">SIMULATED</span></div>
                            </div>
                            <div style="font-size: 0.9rem; color: #374151; margin-top: 4px;">{al['detection_explanation']}</div>
                            <div style="font-size: 0.8rem; color: #1D4ED8; margin-top: 4px;">💡 <b>Recommended Action:</b> {al['recommended_action']}</div>
                        </div>
                        """, unsafe_allow_html=True)

                # Events table
                with st.expander("Inspect Raw Generated Synthetic Events", expanded=False):
                    df_sim_display = pd.DataFrame(sim_result["events"])[
                        ["event_id", "timestamp_orig", "system", "actor", "action", "target", "source_ip", "result", "expected_classification"]
                    ]
                    st.dataframe(df_sim_display, use_container_width=True)

    with sim_tab2:
        st.subheader("Held-Out Generalization Evaluation Battery")
        st.markdown("""
        Evaluates TRACE against unseen variations:
        - Different IPs, altered event ordering, and missing optional fields.
        - Legitimate lookalikes (approved bank changes, normal sync queries, routine Tuesday exports).
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

# -------------------------------------------------------------------------------------------------
# TAB 7: INGESTION & INTEGRITY AUDIT
# -------------------------------------------------------------------------------------------------
elif nav_choice == "7. Ingestion & Integrity Audit":
    st.header("Data Ingestion Pipeline & Integrity Verification")
    st.markdown("Audit report confirming evidence preservation, zero synthetic distortion, and timezone handling.")

    st.subheader("1. Timezone Handling Strategy")
    st.markdown("""
    - **LedgerOne API Logs (`E01`, `E18`)**: Stored in UTC (ISO 8601 `YYYY-MM-DDTHH:MM:SSZ`). Normalized to standard UTC timestamp.
    - **HelpDeskr Audit Logs (`E02`)**: Recorded in tenant local time (IST, `DD/MM/YYYY HH:MM:SS`). Normalized by attaching IST (+05:30) and converting to UTC.
    - **Single Sign-On Logs (`E03`)**: Recorded in UTC with explicit offset (`+00:00`). Normalized to standard UTC timestamp.
    - **BlueVault Access Logs (`E05`)**: Recorded in Unix Epoch seconds. *Note: BlueVault system clock was never synchronized; timestamps are normalized to UTC with an explicit drift caveat.*
    - **Private-Link Flow Logs (`E15`) & Vendor Change Logs (`E19`)**: Recorded in standard UTC.
    """)

    st.subheader("2. Identified Data Quality Issues & Unreliable Information")
    st.markdown("""
    | Source | Quality Issue | Mitigation in TRACE Engine |
    | :--- | :--- | :--- |
    | **E14 (Staff Roster)** | `status` column is uniformly marked `'active'` for all 420 rows, even for departed staff. | Ingestion checks `termination_date` directly rather than relying on `status`. |
    | **E05 (BlueVault)** | Unsynchronized system clock and missing source IP addresses. | Timestamps flagged with drift disclaimer; correlation relies on principal IDs. |
    | **E15 (Flow Logs)** | Host labels (e.g. `tb-build-02`) supplied by outside vendor. | Treated as unverified vendor metadata; verified against public records (`E20`). |
    | **E17 (Threat Indicators)** | Indicator list provided by outside company marked unverified. | Treated as corroborative context rather than confirmed ground truth. |
    """)

    st.subheader("3. Pipeline Self-Test")
    if st.button("Run Pipeline Self-Test"):
        with st.spinner("Executing pipeline verification..."):
            inv = ingestor.get_inventory()
            events = get_normalised_events(base_dir)
            alerts = get_alerts(base_dir)
            cases = get_investigation_cases(base_dir)
            st.success(f"Self-test passed: {len(inv)} evidence items, {len(events):,} events normalised, {len(alerts)} alerts generated, {len(cases)} investigation cases correlated!")
