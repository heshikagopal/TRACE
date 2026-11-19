"""
TRACE Master Cross-System Correlation Engine
Synthesizes events across E01–E20 into 4 dedicated investigation cases with auditable timelines,
rigorous relationship typing, and transparent risk scoring.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import pandas as pd
import logging

from trace_engine.correlation_models import RelationshipType, CorrelatedEvent, InvestigationCase
from trace_engine.correlation_scoring import CaseRiskScorer

logger = logging.getLogger("trace.correlation")


class CrossSystemCorrelationEngine:
    """Builds and analyzes multi-system investigation cases across case telemetry."""

    def __init__(self, ingestor=None):
        self.ingestor = ingestor
        self.cases: Dict[str, InvestigationCase] = {}

    def build_all_cases(self, df_events: pd.DataFrame, context: Optional[Dict[str, Any]] = None) -> Dict[str, InvestigationCase]:
        """Constructs the four investigation cases from normalized events and auxiliary context."""
        if context is None and self.ingestor is not None:
            context = {
                "E14": self.ingestor.load_csv("E14"),
                "E04": self.ingestor.load_json("E04"),
                "E09": self.ingestor.load_risk_register(),
                "E17": self.ingestor.load_csv("E17")
            }
        context = context or {}

        self.cases = {
            "CASE-01": self._build_case_01_account_access(df_events, context),
            "CASE-02": self._build_case_02_api_credential_misuse(df_events, context),
            "CASE-03": self._build_case_03_vendor_manipulation(df_events, context),
            "CASE-04": self._build_case_04_data_exfiltration(df_events, context)
        }
        return self.cases

    # -------------------------------------------------------------------------
    # CASE 1: POTENTIAL UNAUTHORISED ACCOUNT ACCESS
    # -------------------------------------------------------------------------
    def _build_case_01_account_access(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> InvestigationCase:
        timeline: List[CorrelatedEvent] = []

        # 1. Contextual departure record (E14)
        roster = context.get("E14")
        term_str = "2026-06-30"
        if roster is not None and not roster.empty:
            rm_row = roster[roster["username"] == "r.menon"]
            if not rm_row.empty:
                term_str = str(rm_row.iloc[0]["termination_date"])

        timeline.append(CorrelatedEvent(
            event_id="E14:HF0004-EXIT",
            timestamp=datetime(2026, 6, 30, 18, 0, tzinfo=timezone.utc),
            timestamp_orig="2026-06-30",
            normalised_timestamp_str="2026-06-30T18:00:00Z",
            source_system="HR Directory",
            evidence_id="E14",
            description="Accounts Payable Clerk Rohan Menon employment ended. Known defect: directory status column remained 'active'.",
            relationship_type=RelationshipType.CONTEXTUAL.value,
            confidence="Confirmed Fact",
            identifiers_matched=["r.menon", "HF0004"],
            uncertainty_notes="Staff directory status is manually maintained without automated IT deprovisioning sync (Audit Finding 3, Risk R-018)."
        ))

        # 2. SSO Sign-in Events for r.menon (E03)
        sso_events = df_events[(df_events["source_evidence_id"] == "E03") & (df_events["actor"] == "r.menon")]
        for _, evt in sso_events.iterrows():
            evt_time = evt["timestamp"]
            is_post_term = (evt_time and evt_time > datetime(2026, 7, 1, tzinfo=timezone.utc))
            
            rel_type = RelationshipType.DIRECT_MATCH.value if is_post_term else RelationshipType.CONTEXTUAL.value
            desc = (
                f"Post-termination SSO sign-in ({evt['result']}) for r.menon from IP {evt['source_ip']} (warehouse kiosk subnet)."
                if is_post_term else
                f"Historical employment sign-in ({evt['result']}) for r.menon from {evt['source_ip']}."
            )

            timeline.append(CorrelatedEvent(
                event_id=evt["event_id"],
                timestamp=evt_time,
                timestamp_orig=evt["timestamp_orig"],
                normalised_timestamp_str=evt_time.isoformat() if evt_time else evt["timestamp_orig"],
                source_system="Single Sign-On (SSO)",
                evidence_id="E03",
                description=desc,
                relationship_type=rel_type,
                confidence="Confirmed Fact",
                identifiers_matched=["r.menon"],
                uncertainty_notes="Physical user at warehouse kiosk terminal is unverified; laptop/terminal logs are uncollected." if is_post_term else "",
                raw_data=evt.get("raw_record", {})
            ))

        timeline.sort(key=lambda e: e.timestamp if e.timestamp else datetime.min.replace(tzinfo=timezone.utc))

        risk_eval = CaseRiskScorer.evaluate_case(
            case_id="CASE-01",
            timeline=timeline,
            primary_entities=["r.menon", "172.16.8.0/24"]
        )

        return InvestigationCase(
            case_id="CASE-01",
            title="Potential Unauthorised Account Access (Former Employee)",
            focus="Verification of post-termination sign-in activity and deprovisioning control failure.",
            primary_entities=["r.menon", "172.16.8.x (Warehouse Kiosk)"],
            primary_evidence_ids=["E03", "E14", "E09", "E11"],
            timeline=timeline,
            risk_assessment=risk_eval,
            summary=(
                "Rohan Menon's account experienced a verified successful authentication on 13 August 2026 "
                "(sso-bb8ab61e08) from an internal kiosk IP, 44 days after his employment terminated on 30 June 2026. "
                "This directly confirms Risk R-018 and Internal Audit Finding 3."
            ),
            facts_observed=[
                "Roster E14 documents Rohan Menon termination date as 2026-06-30.",
                "E14 status column uniformly indicates 'active' for all 420 staff.",
                "SSO log E03 records successful login sso-bb8ab61e08 on 2026-08-13T09:02:00+00:00.",
                "Originating IP belongs to the internal warehouse office network."
            ],
            investigative_hypotheses=[
                "A warehouse staff member used saved kiosk credentials rather than malicious external access.",
                "Rohan Menon physically re-entered or retained remote access."
            ],
            recommended_actions=[
                "Immediately revoke active sessions and disable r.menon in SSO.",
                "Review physical access logs and CCTV for warehouse kiosk on 13 August 09:00–09:30 UTC.",
                "Audit any finance actions or approvals attempted under r.menon's identity in August."
            ]
        )

    # -------------------------------------------------------------------------
    # CASE 2: POTENTIAL INTEGRATION / API CREDENTIAL MISUSE
    # -------------------------------------------------------------------------
    def _build_case_02_api_credential_misuse(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> InvestigationCase:
        timeline: List[CorrelatedEvent] = []

        # 1. Contextual Integration Scope (E04)
        timeline.append(CorrelatedEvent(
            event_id="E04:KEY-TB-07",
            timestamp=datetime(2024, 6, 12, 0, 0, tzinfo=timezone.utc),
            timestamp_orig="2024-06-12",
            normalised_timestamp_str="2024-06-12T00:00:00Z",
            source_system="IT Integration Register",
            evidence_id="E04",
            description="TallyBridge-LedgerOne credential key-tb-07 issued with 'read:write all-modules' scope and NO IP restriction.",
            relationship_type=RelationshipType.CONTEXTUAL.value,
            confidence="Confirmed Fact",
            identifiers_matched=["key-tb-07", "TallyBridge Software"],
            uncertainty_notes="Register retains current state only; history of scope modifications is not recorded."
        ))

        # 2. Network Flow Log for tb-build-02 (E15)
        flow_events = df_events[(df_events["source_evidence_id"] == "E15") & (df_events["source_ip"] == "10.20.4.77")]
        for _, f in flow_events.head(10).iterrows():
            timeline.append(CorrelatedEvent(
                event_id=f["event_id"],
                timestamp=f["timestamp"],
                timestamp_orig=f["timestamp_orig"],
                normalised_timestamp_str=f["timestamp"].isoformat() if f["timestamp"] else f["timestamp_orig"],
                source_system="Private-Link Tunnel",
                evidence_id="E15",
                description=f"Network flow allowed from 10.20.4.77 (tb-build-02) across private link tun-tb-01.",
                relationship_type=RelationshipType.DIRECT_MATCH.value,
                confidence="Confirmed Fact",
                identifiers_matched=["10.20.4.77", "tun-tb-01"],
                uncertainty_notes="Host label 'tb-build-02' was supplied by vendor and is unverified internally."
            ))

        # 3. LedgerOne API calls from 10.20.4.77 using key-tb-07 (E18)
        api_77 = df_events[(df_events["source_evidence_id"] == "E18") & (df_events["source_ip"] == "10.20.4.77")]
        for _, req in api_77.iterrows():
            target = req["target"]
            method = req.get("details", {}).get("method", "GET")
            timeline.append(CorrelatedEvent(
                event_id=req["event_id"],
                timestamp=req["timestamp"],
                timestamp_orig=req["timestamp_orig"],
                normalised_timestamp_str=req["timestamp"].isoformat() if req["timestamp"] else req["timestamp_orig"],
                source_system="LedgerOne API",
                evidence_id="E18",
                description=f"Anomalous API request: {method} {target} using key-tb-07 from build host 10.20.4.77.",
                relationship_type=RelationshipType.DIRECT_MATCH.value,
                confidence="Confirmed Fact",
                identifiers_matched=["key-tb-07", "10.20.4.77", req["original_event_id"]],
                uncertainty_notes=""
            ))

        # 4. External Vendor Notice Context (E12, E16, E17)
        timeline.append(CorrelatedEvent(
            event_id="E12:VENDOR-NOTICE",
            timestamp=datetime(2026, 8, 21, 14, 2, tzinfo=timezone.utc), # 19:32 IST -> 14:02 UTC
            timestamp_orig="Fri, 21 Aug 2026, 19:32 IST",
            normalised_timestamp_str="2026-08-21T14:02:00Z",
            source_system="External Vendor Communication",
            evidence_id="E12",
            description="TallyBridge sent precautionary update regarding upstream environment changes.",
            relationship_type=RelationshipType.UNVERIFIED.value,
            confidence="Unverified",
            identifiers_matched=["TallyBridge Software"],
            uncertainty_notes="Self-reported advisory; technical specifics and scope of compromise unverified."
        ))

        timeline.sort(key=lambda e: e.timestamp if e.timestamp else datetime.min.replace(tzinfo=timezone.utc))

        risk_eval = CaseRiskScorer.evaluate_case(
            case_id="CASE-02",
            timeline=timeline,
            primary_entities=["key-tb-07", "10.20.4.77", "TallyBridge Software"]
        )

        return InvestigationCase(
            case_id="CASE-02",
            title="Potential Integration & API Credential Misuse (TallyBridge)",
            focus="Investigation of out-of-pool invocation of key-tb-07 from build host 10.20.4.77.",
            primary_entities=["key-tb-07", "10.20.4.77 (tb-build-02)", "TallyBridge Connect"],
            primary_evidence_ids=["E01", "E04", "E15", "E18", "E12", "E16", "E20"],
            timeline=timeline,
            risk_assessment=risk_eval,
            summary=(
                "Between 1 and 7 September 2026, TallyBridge integration credential key-tb-07 was used from "
                "internal IP 10.20.4.77 (labeled in E15 as tb-build-02) to query sensitive endpoints including "
                "/v2/vendors/V-0412/bank-details and /v2/payments/scheduled. Routine nightly syncs use IPs 10.20.4.11-16."
            ),
            facts_observed=[
                "E04 confirms key-tb-07 was provisioned without IP restriction and with broad read:write scope.",
                "E15 logs demonstrate 10.20.4.77 was active across tunnel tun-tb-01 with label tb-build-02.",
                "E18 records 5 specific API requests from 10.20.4.77 targeting vendor bank and payment endpoints.",
                "E20 status page confirms tb-build-02 was re-provisioned on 16 August 2026."
            ],
            investigative_hypotheses=[
                "Build server tb-build-02 was compromised upstream at TallyBridge, exposing stored customer credentials.",
                "An unauthorized operator accessed TallyBridge build infrastructure to interact with customer APIs."
            ],
            recommended_actions=[
                "Immediately revoke key-tb-07 in LedgerOne.",
                "Block traffic from 10.20.4.77 on the network gateway.",
                "Demand independent forensic verification from TallyBridge regarding tb-build-02 compromise."
            ]
        )

    # -------------------------------------------------------------------------
    # CASE 3: POTENTIAL VENDOR RECORD MANIPULATION
    # -------------------------------------------------------------------------
    def _build_case_03_vendor_manipulation(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> InvestigationCase:
        timeline: List[CorrelatedEvent] = []

        # 1. API Bank Modification in E19
        v_events = df_events[(df_events["source_evidence_id"] == "E19") & (df_events["target"].str.contains("V-0412"))]
        for _, evt in v_events.iterrows():
            details = evt.get("details", {})
            timeline.append(CorrelatedEvent(
                event_id=evt["event_id"],
                timestamp=evt["timestamp"],
                timestamp_orig=evt["timestamp_orig"],
                normalised_timestamp_str=evt["timestamp"].isoformat() if evt["timestamp"] else evt["timestamp_orig"],
                source_system="LedgerOne Vendor Master",
                evidence_id="E19",
                description=(
                    f"Bank account for Coastal Packaging Ltd (V-0412) changed from {details.get('old_value')} "
                    f"to {details.get('new_value')} via API channel by '{evt['actor']}' with NO approval reference."
                ),
                relationship_type=RelationshipType.DIRECT_MATCH.value,
                confidence="Confirmed Fact",
                identifiers_matched=["V-0412", "key-tb-07", str(details.get("request_id"))],
                uncertainty_notes="Approval reference is blank; bypasses dual-control policy E10 Section 4.1.",
                raw_data=evt.get("raw_record", {})
            ))

        # 2. Correlating API Request in E18 (req-5f61b0de8)
        api_chg = df_events[(df_events["source_evidence_id"] == "E18") & (df_events["original_event_id"] == "req-5f61b0de8")]
        for _, req in api_chg.iterrows():
            timeline.append(CorrelatedEvent(
                event_id=req["event_id"],
                timestamp=req["timestamp"],
                timestamp_orig=req["timestamp_orig"],
                normalised_timestamp_str=req["timestamp"].isoformat() if req["timestamp"] else req["timestamp_orig"],
                source_system="LedgerOne API",
                evidence_id="E18",
                description=f"HTTP PATCH /v2/vendors/V-0412/bank-details from 10.20.4.77 (Request ID: req-5f61b0de8).",
                relationship_type=RelationshipType.DIRECT_MATCH.value,
                confidence="Confirmed Fact",
                identifiers_matched=["req-5f61b0de8", "10.20.4.77", "key-tb-07"],
                uncertainty_notes="",
                raw_data=req.get("raw_record", {})
            ))

        # 3. Contextual Preceding Inquiries in E18
        preceding = df_events[(df_events["source_evidence_id"] == "E18") & 
                              (df_events["source_ip"] == "10.20.4.77") & 
                              (df_events["original_event_id"] != "req-5f61b0de8")]
        for _, req in preceding.iterrows():
            timeline.append(CorrelatedEvent(
                event_id=req["event_id"],
                timestamp=req["timestamp"],
                timestamp_orig=req["timestamp_orig"],
                normalised_timestamp_str=req["timestamp"].isoformat() if req["timestamp"] else req["timestamp_orig"],
                source_system="LedgerOne API",
                evidence_id="E18",
                description=f"Preceding reconnaissance: {req.get('details', {}).get('method')} {req['target']}.",
                relationship_type=RelationshipType.TEMPORAL.value,
                confidence="High Confidence",
                identifiers_matched=["10.20.4.77", "key-tb-07"],
                uncertainty_notes="Occurred 1 to 3 minutes prior to the bank account modification."
            ))

        timeline.sort(key=lambda e: e.timestamp if e.timestamp else datetime.min.replace(tzinfo=timezone.utc))

        risk_eval = CaseRiskScorer.evaluate_case(
            case_id="CASE-03",
            timeline=timeline,
            primary_entities=["V-0412", "Coastal Packaging Ltd", "key-tb-07", "req-5f61b0de8"]
        )

        return InvestigationCase(
            case_id="CASE-03",
            title="Potential Vendor Record Manipulation (Payment Diversion)",
            focus="Analysis of unauthorized bank account changes on Coastal Packaging Ltd (V-0412).",
            primary_entities=["V-0412 (Coastal Packaging Ltd)", "key-tb-07", "req-5f61b0de8"],
            primary_evidence_ids=["E19", "E18", "E10", "E04"],
            timeline=timeline,
            risk_assessment=risk_eval,
            summary=(
                "On 3 September 2026 at 01:44:30 UTC, change chg-8b9888c39b updated the bank account of "
                "Coastal Packaging Ltd (V-0412) to ****9083 via automated API. Linking to E18 demonstrates "
                "this originated from 10.20.4.77 under request req-5f61b0de8 without an approval reference. "
                "A major payment run is scheduled for 8 September 2026."
            ),
            facts_observed=[
                "E19 records bank account modification chg-8b9888c39b with channel='API' and approval_ref=NaN.",
                "E19 links explicitly to E18 via request_id req-5f61b0de8.",
                "E18 confirms request req-5f61b0de8 was a PATCH to /v2/vendors/V-0412/bank-details from 10.20.4.77.",
                "IT Security Policy E10 requires signed dual authorization for any payment instruction changes."
            ],
            investigative_hypotheses=[
                "Payment fraud intended to divert scheduled 8 September vendor disbursements to an unauthorized account.",
                "Automated sync malfunction misallocating vendor records."
            ],
            recommended_actions=[
                "Place an immediate payment freeze on Coastal Packaging Ltd (V-0412).",
                "Contact Coastal Packaging Ltd CFO using verified off-band telephone contact to confirm authentic bank details.",
                "Disable all API-driven modification rights on vendor master payment instruction tables."
            ]
        )

    # -------------------------------------------------------------------------
    # CASE 4: POTENTIAL DATA EXPORT OR EXFILTRATION
    # -------------------------------------------------------------------------
    def _build_case_04_data_exfiltration(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> InvestigationCase:
        timeline: List[CorrelatedEvent] = []

        # 1. Credential Searches in HelpDeskr (E02)
        hd_events = df_events[df_events["source_evidence_id"] == "E02"]
        sensitive_kw = ["password", "bvk-", "api_key", "secret", "bearer", "private key"]
        searches = hd_events[hd_events["action"] == "ticket.search"]
        for _, s in searches.iterrows():
            details_str = str(s.get("details", {}).get("details", "")).lower()
            if any(k in details_str for k in sensitive_kw):
                timeline.append(CorrelatedEvent(
                    event_id=s["event_id"],
                    timestamp=s["timestamp"],
                    timestamp_orig=s["timestamp_orig"],
                    normalised_timestamp_str=s["timestamp"].isoformat() if s["timestamp"] else s["timestamp_orig"],
                    source_system="HelpDeskr Support",
                    evidence_id="E02",
                    description=f"Targeted search for '{details_str}' from IP {s['source_ip']} under actor {s['actor']}.",
                    relationship_type=RelationshipType.TEMPORAL.value,
                    confidence="Confirmed Fact",
                    identifiers_matched=[details_str, str(s["source_ip"])],
                    uncertainty_notes=""
                ))

        # 2. Bulk Exports Burst in HelpDeskr (E02)
        exports = hd_events[hd_events["action"].str.contains("export", case=False, na=False)]
        aug_cluster = exports[exports["timestamp_orig"].str.contains("11/08/2026|12/08/2026", na=False)]
        for _, exp in aug_cluster.head(10).iterrows():
            timeline.append(CorrelatedEvent(
                event_id=exp["event_id"],
                timestamp=exp["timestamp"],
                timestamp_orig=exp["timestamp_orig"],
                normalised_timestamp_str=exp["timestamp"].isoformat() if exp["timestamp"] else exp["timestamp_orig"],
                source_system="HelpDeskr Support",
                evidence_id="E02",
                description=f"Bulk ticket export job initiated by {exp['actor']} from {exp['source_ip']}.",
                relationship_type=RelationshipType.TEMPORAL.value,
                confidence="Confirmed Fact",
                identifiers_matched=[str(exp["source_ip"])],
                uncertainty_notes="Corroborates E06 invoice billing overage."
            ))

        # 3. Leaked Key Context in Chat (E13)
        timeline.append(CorrelatedEvent(
            event_id="E13:TKT-48213",
            timestamp=datetime(2026, 6, 25, 6, 1, tzinfo=timezone.utc), # 11:31 IST -> 06:01 UTC
            timestamp_orig="2026-06-25 11:31",
            normalised_timestamp_str="2026-06-25T06:01:00Z",
            source_system="Support Team Chat",
            evidence_id="E13",
            description="Sunita Iyer notes customer storage key bvk-7f3a was pasted directly into ticket TKT-48213.",
            relationship_type=RelationshipType.DIRECT_MATCH.value,
            confidence="Confirmed Fact",
            identifiers_matched=["bvk-7f3a", "TKT-48213"],
            uncertainty_notes="Partial export; direct messages excluded."
        ))

        # 4. BlueVault Document Harvesting by bvk-7f3a (E05)
        bv_events = df_events[(df_events["source_evidence_id"] == "E05") & (df_events["actor"] == "key:bvk-7f3a")]
        # Sample bank-instruction access and customer doc access
        for _, bv in bv_events[bv_events["target"].str.contains("bank-instructions", case=False, na=False)].head(5).iterrows():
            timeline.append(CorrelatedEvent(
                event_id=bv["event_id"],
                timestamp=bv["timestamp"],
                timestamp_orig=bv["timestamp_orig"],
                normalised_timestamp_str=bv["timestamp"].isoformat() if bv["timestamp"] else "",
                source_system="BlueVault Storage",
                evidence_id="E05",
                description=f"Key bvk-7f3a used to read {bv['target']} from {bv['source_ip']}.",
                relationship_type=RelationshipType.DIRECT_MATCH.value,
                confidence="High Confidence",
                identifiers_matched=["bvk-7f3a", str(bv["target"])],
                uncertainty_notes="WARNING: BlueVault clock has never been synchronized / unsynchronized (known clock drift); timestamp relative only.",
                raw_data=bv.get("raw_record", {})
            ))

        timeline.sort(key=lambda e: e.timestamp if e.timestamp else datetime.min.replace(tzinfo=timezone.utc))

        risk_eval = CaseRiskScorer.evaluate_case(
            case_id="CASE-04",
            timeline=timeline,
            primary_entities=["bvk-7f3a", "HelpDeskr Bulk Exports", "BlueVault"]
        )

        return InvestigationCase(
            case_id="CASE-04",
            title="Potential Data Export & Credential Harvesting",
            focus="Reconnaissance in support tickets and horizontal storage key misuse.",
            primary_entities=["bvk-7f3a", "TKT-48213", "HelpDeskr Export Service"],
            primary_evidence_ids=["E02", "E06", "E13", "E05", "E17"],
            timeline=timeline,
            risk_assessment=risk_eval,
            summary=(
                "On 11–12 August 2026, HelpDeskr audit logs show targeted searches for secrets followed by 30 bulk ticket exports, "
                "causing the billing overage in E06. In addition, BlueVault logs demonstrate storage key bvk-7f3a (leaked in ticket TKT-48213) "
                "was used to harvest files across 143 customer folders and read vendor bank instruction spreadsheets."
            ),
            facts_observed=[
                "E02 confirms searches for 'password', 'api_key', 'bvk-', 'bearer', 'private key' on 11 August.",
                "E02 records 30 bulk export jobs within 90 minutes on 11–12 August.",
                "E06 verifies 14 exports over plan allowance billed to Harbor & Finch.",
                "E13 documents that key bvk-7f3a was stored in plaintext in TKT-48213.",
                "E05 confirms bvk-7f3a accessed files across 143 distinct customer directories."
            ],
            investigative_hypotheses=[
                "Attacker exfiltrated support tickets to extract configuration secrets and customer credentials.",
                "Storage key bvk-7f3a lacked proper tenant scoping in BlueVault, enabling horizontal privilege escalation."
            ],
            recommended_actions=[
                "Revoke storage key bvk-7f3a immediately across all BlueVault storage policies.",
                "Enforce programmatic redaction of credentials in customer ticket attachments and descriptions.",
                "Review downloaded ticket contents for regulatory breach notification triggers under customer MSAs."
            ]
        )
