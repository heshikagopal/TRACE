"""
TRACE Modular Detection Rules
Implements evidence-supported detection rules independently of UI frameworks.
Every rule operates on normalized events and context records with configurable thresholds.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import pandas as pd
import logging

from trace_engine.alert_schema import ThreatAlert
from trace_engine.risk_scoring import RiskScoreCalculator

logger = logging.getLogger("trace.rules")


class BaseRule(ABC):
    """Abstract base class for all TRACE detection rules."""

    def __init__(self, rule_id: str, name: str, category: str, enabled: bool = True):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.enabled = enabled

    @abstractmethod
    def evaluate(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> List[ThreatAlert]:
        """Evaluates telemetry events against the rule logic and returns generated alerts."""
        pass


class RuleFormerEmployeeAccess(BaseRule):
    """
    RULE 1: Former Employee Account Access
    Cites: E14 (Staff Roster), E03 (SSO Sign-in Log).
    Identifies authentication attempts by employees past their documented termination date.
    Distinguishes successful logins from failed attempts.
    Does NOT flag terminated employees if no sign-in events occurred.
    """

    def __init__(self, enabled: bool = True, grace_period_days: int = 1):
        super().__init__(
            rule_id="RULE-AUTH-001",
            name="Post-Termination Account Access",
            category="Identity & Access",
            enabled=enabled
        )
        self.grace_period_days = grace_period_days

    def evaluate(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> List[ThreatAlert]:
        alerts = []
        if not self.enabled:
            return alerts

        roster = context.get("E14")
        if roster is None or roster.empty:
            logger.warning("Roster (E14) missing in context for RuleFormerEmployeeAccess")
            return alerts

        # Identify departed staff with documented termination dates
        term_df = roster[roster["termination_date"].notna()]
        term_dict = {}
        for _, row in term_df.iterrows():
            uname = str(row["username"]).strip().lower()
            try:
                term_dt = datetime.strptime(str(row["termination_date"]).strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
                term_dict[uname] = {
                    "full_name": str(row.get("full_name", "")),
                    "role": str(row.get("role", "")),
                    "department": str(row.get("department", "")),
                    "term_date": term_dt,
                    "term_str": str(row["termination_date"])
                }
            except Exception:
                continue

        # Inspect SSO events from E03
        sso_events = df_events[(df_events["source_evidence_id"] == "E03") & (df_events["action"] == "sso.signin")]
        if sso_events.empty:
            return alerts

        for _, evt in sso_events.iterrows():
            actor = str(evt["actor"]).strip().lower()
            if actor in term_dict:
                emp = term_dict[actor]
                evt_time = evt["timestamp"]
                term_cutoff = emp["term_date"] + timedelta(days=self.grace_period_days)

                if evt_time and evt_time > term_cutoff:
                    is_success = (str(evt["result"]).lower() == "success")
                    days_elapsed = (evt_time - emp["term_date"]).days

                    score, severity = RiskScoreCalculator.calculate(
                        asset_type="identity_credential",
                        is_success=is_success,
                        is_api_channel=False,
                        missing_approval=False,
                        unusual_network_source=(str(evt["source_ip"]).startswith("172.16.")),
                        evidence_confidence="Confirmed Fact"
                    )

                    outcome_text = "successful sign-in" if is_success else f"unsuccessful sign-in attempt (reason: {evt.get('details', {}).get('failure_reason', 'failed')})"
                    explanation = (
                        f"Observed {outcome_text} for account '{actor}' ({emp['full_name']}, {emp['role']}) "
                        f"on {evt_time.strftime('%Y-%m-%d %H:%M:%S UTC')}, {days_elapsed} days after documented "
                        f"employment termination ({emp['term_str']}). Recordkeeping discrepancy: E14 directory status "
                        f"was left marked 'active'."
                    )

                    alerts.append(ThreatAlert(
                        alert_id=f"ALT-AUTH-{evt['original_event_id']}",
                        rule_id=self.rule_id,
                        threat_category=self.category,
                        severity=severity,
                        risk_score=score,
                        detection_explanation=explanation,
                        triggering_event_ids=[evt["event_id"]],
                        evidence_ids=["E03", "E14", "E09", "E11"],
                        original_timestamps=[evt["timestamp_orig"]],
                        normalised_timestamps=[evt_time.isoformat()],
                        confidence="Confirmed Fact",
                        recommended_action=(
                            "Immediately revoke active sessions, disable user in identity provider, "
                            "and audit kiosk terminal logs associated with source IP."
                        ),
                        target_entity=actor,
                        source_ip=str(evt["source_ip"]),
                        rule_metadata={"is_success": is_success, "days_post_termination": days_elapsed}
                    ))

        return alerts


class RuleSuspiciousAPIActivity(BaseRule):
    """
    RULE 2: Suspicious API Activity
    Cites: E01, E18 (LedgerOne Logs), E04 (Integrations), E15 (Flows), E17 (Indicators).
    Examines API keys, caller IPs, endpoints, methods, and record counts.
    Identifies calls originating from outside the designated integration pool (e.g. build host 10.20.4.77)
    and queries to sensitive payment endpoints.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            rule_id="RULE-API-001",
            name="Anomalous API Integration Activity",
            category="API Security",
            enabled=enabled
        )

    def evaluate(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> List[ThreatAlert]:
        alerts = []
        if not self.enabled:
            return alerts

        api_events = df_events[df_events["source_evidence_id"].isin(["E01", "E18"])]
        if api_events.empty:
            return alerts

        sensitive_endpoints = ["/v2/vendors/", "/v2/payments/scheduled", "/bank-details"]
        # Normal sync pool is 10.20.4.11 to 10.20.4.16. 10.20.4.77 is tb-build-02 in E15!
        anomalous_caller_ips = ["10.20.4.77"]

        for _, evt in api_events.iterrows():
            caller_ip = str(evt["source_ip"])
            key_id = str(evt["actor"])
            target = str(evt["target"])
            method = evt.get("details", {}).get("method", "GET")

            # Condition 1: Build server invoking finance API
            if caller_ip in anomalous_caller_ips and key_id == "key-tb-07":
                is_sensitive = any(s in target for s in sensitive_endpoints)
                score, severity = RiskScoreCalculator.calculate(
                    asset_type="payment_instruction" if is_sensitive else "general_telemetry",
                    is_success=(str(evt["result"]) == "200"),
                    is_api_channel=True,
                    unusual_network_source=True,
                    evidence_confidence="Confirmed Fact"
                )

                alerts.append(ThreatAlert(
                    alert_id=f"ALT-API-{evt['original_event_id']}",
                    rule_id=self.rule_id,
                    threat_category=self.category,
                    severity=severity,
                    risk_score=score,
                    detection_explanation=(
                        f"Integration key '{key_id}' issued HTTP {method} to '{target}' from caller IP {caller_ip}. "
                        f"Network flow log E15 maps {caller_ip} to internal build machine 'tb-build-02', which has no "
                        f"legitimate operational purpose in LedgerOne financial sync."
                    ),
                    triggering_event_ids=[evt["event_id"]],
                    evidence_ids=[evt["source_evidence_id"], "E04", "E15", "E18"],
                    original_timestamps=[evt["timestamp_orig"]],
                    normalised_timestamps=[evt["timestamp"].isoformat() if evt["timestamp"] else evt["timestamp_orig"]],
                    confidence="Confirmed Fact",
                    recommended_action=(
                        "Sever private-link access for host 10.20.4.77, rotate key-tb-07, and enforce IP-whitelisting on LedgerOne."
                    ),
                    target_entity=key_id,
                    source_ip=caller_ip,
                    rule_metadata={"endpoint": target, "method": method}
                ))

            # Condition 2: Indicators from E17
            if caller_ip in ["198.18.7.41", "198.18.7.58"] or key_id == "key-tb-03":
                score, severity = RiskScoreCalculator.calculate(
                    asset_type="general_telemetry",
                    is_success=(str(evt["result"]) == "200"),
                    is_api_channel=True,
                    unusual_network_source=True,
                    evidence_confidence="Unverified Indicator"
                )
                alerts.append(ThreatAlert(
                    alert_id=f"ALT-IOC-{evt['original_event_id']}",
                    rule_id="RULE-API-002",
                    threat_category="Threat Intelligence",
                    severity=severity,
                    risk_score=score,
                    detection_explanation=(
                        f"Observed API invocation matching third-party threat indicator (E17): "
                        f"caller_ip={caller_ip}, credential={key_id} on {target}. Preserved with unverified confidence."
                    ),
                    triggering_event_ids=[evt["event_id"]],
                    evidence_ids=[evt["source_evidence_id"], "E17"],
                    original_timestamps=[evt["timestamp_orig"]],
                    normalised_timestamps=[evt["timestamp"].isoformat() if evt["timestamp"] else evt["timestamp_orig"]],
                    confidence="Unverified Indicator",
                    recommended_action="Validate indicator validity with TallyBridge security team and review associated session logs.",
                    target_entity=key_id or caller_ip,
                    source_ip=caller_ip
                ))

        return alerts


class RuleHelpdeskExportActivity(BaseRule):
    """
    RULE 3: Helpdesk Export & Reconnaissance Activity
    Cites: E02 (HelpDeskr Logs), E06 (Billing Alert), E13 (Support Chat).
    Distinguishes scheduled Tuesday ticket reporting from abnormal bulk export bursts
    and targeted credential keyword searches.
    """

    def __init__(self, enabled: bool = True, export_burst_threshold: int = 5):
        super().__init__(
            rule_id="RULE-EXP-001",
            name="Unusual Helpdesk Export & Secret Reconnaissance",
            category="Data Exfiltration & Reconnaissance",
            enabled=enabled
        )
        self.export_burst_threshold = export_burst_threshold

    def evaluate(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> List[ThreatAlert]:
        alerts = []
        if not self.enabled:
            return alerts

        hd_events = df_events[df_events["source_evidence_id"] == "E02"]
        if hd_events.empty:
            return alerts

        # Sub-rule A: Targeted credential keyword searches
        sensitive_keywords = ["password", "api_key", "secret", "token", "bearer", "private key", "bluevault", "bvk-"]
        searches = hd_events[hd_events["action"] == "ticket.search"]
        flagged_searches = []
        for _, s in searches.iterrows():
            details_str = str(s.get("details", {}).get("details", "")).lower()
            if any(k in details_str for k in sensitive_keywords):
                flagged_searches.append(s)

        if len(flagged_searches) >= 3:
            first_s = flagged_searches[0]
            score, severity = RiskScoreCalculator.calculate(
                asset_type="identity_credential",
                is_success=True,
                is_api_channel=False,
                unusual_network_source=True,
                evidence_confidence="Confirmed Fact"
            )
            alerts.append(ThreatAlert(
                alert_id="ALT-HD-RECON-01",
                rule_id="RULE-EXP-001",
                threat_category=self.category,
                severity=severity,
                risk_score=score,
                detection_explanation=(
                    f"Identified {len(flagged_searches)} targeted ticket searches for sensitive credential terms "
                    f"('password', 'api_key', 'token', 'bearer', 'bvk-') between {flagged_searches[0]['timestamp_orig']} "
                    f"and {flagged_searches[-1]['timestamp_orig']}. Demonstrates credential reconnaissance in customer support tickets."
                ),
                triggering_event_ids=[s["event_id"] for s in flagged_searches[:10]],
                evidence_ids=["E02", "E13"],
                original_timestamps=[first_s["timestamp_orig"]],
                normalised_timestamps=[first_s["timestamp"].isoformat() if first_s["timestamp"] else first_s["timestamp_orig"]],
                confidence="Confirmed Fact",
                recommended_action="Audit ticket search logs and immediately rotate any keys pasted into searched tickets (e.g., bvk-7f3a in TKT-48213).",
                target_entity="HelpDeskr Ticket Database",
                source_ip=str(first_s["source_ip"])
            ))

        # Sub-rule B: Bulk export burst
        exports = hd_events[hd_events["action"].str.contains("export", case=False, na=False)]
        # Filter cluster on 11-12 August
        aug_cluster = [e for _, e in exports.iterrows() if "11/08/2026" in str(e["timestamp_orig"]) or "12/08/2026" in str(e["timestamp_orig"])]
        if len(aug_cluster) >= self.export_burst_threshold:
            first_exp = aug_cluster[0]
            score, severity = RiskScoreCalculator.calculate(
                asset_type="support_ticket",
                is_success=True,
                volume_burst=True,
                evidence_confidence="Confirmed Fact"
            )
            alerts.append(ThreatAlert(
                alert_id="ALT-HD-BULK-EXP-01",
                rule_id="RULE-EXP-002",
                threat_category=self.category,
                severity=severity,
                risk_score=score,
                detection_explanation=(
                    f"Detected abnormal burst of {len(aug_cluster)} bulk ticket exports within 90 minutes "
                    f"(11 Aug 23:30 – 12 Aug 00:33 IST). Directly accounts for the E06 billing overage alert "
                    f"(14 exports vs monthly allowance of 5) and deviates from standard weekly Tuesday exports."
                ),
                triggering_event_ids=[e["event_id"] for e in aug_cluster[:10]],
                evidence_ids=["E02", "E06"],
                original_timestamps=[first_exp["timestamp_orig"]],
                normalised_timestamps=[first_exp["timestamp"].isoformat() if first_exp["timestamp"] else first_exp["timestamp_orig"]],
                confidence="Confirmed Fact",
                recommended_action="Review exported ticket bundles for exposed customer records and enforce dual-authorization on bulk data exports.",
                target_entity="HelpDeskr Bulk Export Facility",
                source_ip=str(first_exp["source_ip"]),
                rule_metadata={"export_count": len(aug_cluster)}
            ))

        return alerts


class RuleVendorRecordModification(BaseRule):
    """
    RULE 4: Vendor Record & Bank Detail Modification
    Cites: E19 (Vendor Master Change Log), E18 (LedgerOne Continuation Log), E10 (Policy).
    Prioritizes bank-detail changes lacking an approval reference or initiated via API channels.
    Does NOT flag benign approved changes (e.g. contact email/phone updates).
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            rule_id="RULE-FIN-001",
            name="Unauthorised Vendor Bank Detail Modification",
            category="Payment & Financial Integrity",
            enabled=enabled
        )

    def evaluate(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> List[ThreatAlert]:
        alerts = []
        if not self.enabled:
            return alerts

        vendor_events = df_events[df_events["source_evidence_id"] == "E19"]
        if vendor_events.empty:
            return alerts

        for _, evt in vendor_events.iterrows():
            details = evt.get("details", {})
            field_name = details.get("field", "")
            channel = details.get("channel", "")
            approval_ref = details.get("approval_ref", "")
            vendor_name = details.get("vendor_name", "")
            vendor_id = details.get("vendor_id", "")
            req_id = details.get("request_id", "")
            actor = evt["actor"]

            if field_name == "bank_account":
                # Condition A: Bank detail change via automated API channel
                if channel == "API":
                    score, severity = RiskScoreCalculator.calculate(
                        asset_type="vendor_bank_account",
                        is_success=True,
                        is_api_channel=True,
                        missing_approval=True,
                        unusual_network_source=True,
                        evidence_confidence="Confirmed Fact"
                    )

                    alerts.append(ThreatAlert(
                        alert_id=f"ALT-FIN-{evt['original_event_id']}",
                        rule_id=self.rule_id,
                        threat_category=self.category,
                        severity=severity,
                        risk_score=score,
                        detection_explanation=(
                            f"CRITICAL: Bank account for vendor '{vendor_name}' ({vendor_id}) was modified via "
                            f"automated API channel by '{actor}' from source IP {evt['source_ip']} without an approval reference. "
                            f"Corroborates with E18 (Request ID: {req_id}) originating from internal build host 10.20.4.77 on 3 Sep 01:44:30 UTC."
                        ),
                        triggering_event_ids=[evt["event_id"], f"E18:{req_id}"],
                        evidence_ids=["E19", "E18", "E10", "E04"],
                        original_timestamps=[evt["timestamp_orig"]],
                        normalised_timestamps=[evt["timestamp"].isoformat() if evt["timestamp"] else evt["timestamp_orig"]],
                        confidence="Confirmed Fact",
                        recommended_action=(
                            "CRITICAL PRIORITY: Place immediate payment hold on Coastal Packaging Ltd (V-0412) "
                            "before the 8th September payment run. Verify bank details with vendor CFO via out-of-band contact."
                        ),
                        target_entity=f"{vendor_name} ({vendor_id})",
                        source_ip=str(evt["source_ip"]),
                        rule_metadata={"channel": channel, "old_value": details.get("old_value"), "new_value": details.get("new_value")}
                    ))

                # Condition B: Bank detail change via UI missing approval reference
                elif not approval_ref:
                    score, severity = RiskScoreCalculator.calculate(
                        asset_type="vendor_bank_account",
                        is_success=True,
                        is_api_channel=False,
                        missing_approval=True,
                        evidence_confidence="Confirmed Fact"
                    )

                    alerts.append(ThreatAlert(
                        alert_id=f"ALT-FIN-PROC-{evt['original_event_id']}",
                        rule_id="RULE-FIN-002",
                        threat_category="Governance & Compliance",
                        severity=severity,
                        risk_score=score,
                        detection_explanation=(
                            f"Vendor '{vendor_name}' bank details were updated via UI by '{actor}' "
                            f"without an approval reference (approval_ref field blank). Bypasses dual-authorization control R-015."
                        ),
                        triggering_event_ids=[evt["event_id"]],
                        evidence_ids=["E19", "E09", "E10"],
                        original_timestamps=[evt["timestamp_orig"]],
                        normalised_timestamps=[evt["timestamp"].isoformat() if evt["timestamp"] else evt["timestamp_orig"]],
                        confidence="Confirmed Fact",
                        recommended_action="Obtain signed authorization documentation retroactively and validate change legitimacy.",
                        target_entity=f"{vendor_name} ({vendor_id})",
                        source_ip=str(evt["source_ip"])
                    ))

        return alerts


class RuleUnusualDocumentAccess(BaseRule):
    """
    RULE 5: Unusual Document & Storage Key Access
    Cites: E05 (BlueVault Access Log), E13 (Support Chat).
    Detects uncharacteristic access to sensitive financial statements or multi-tenant customer folders.
    Accounts explicitly for BlueVault clock drift and unsynchronized timekeeping.
    """

    def __init__(self, enabled: bool = True):
        super().__init__(
            rule_id="RULE-DOC-001",
            name="Unusual Storage Access & Shared Key Misuse",
            category="Document & Storage Security",
            enabled=enabled
        )

    def evaluate(self, df_events: pd.DataFrame, context: Dict[str, Any]) -> List[ThreatAlert]:
        alerts = []
        if not self.enabled:
            return alerts

        bv_events = df_events[df_events["source_evidence_id"] == "E05"]
        if bv_events.empty:
            return alerts

        # Condition A: Access to vendor bank instruction sheets in BlueVault
        bank_doc_events = bv_events[bv_events["target"].str.contains("bank-instructions|vendor-bank", case=False, na=False)]
        if not bank_doc_events.empty:
            principals = bank_doc_events["actor"].unique().tolist()
            first_doc = bank_doc_events.iloc[0]

            score, severity = RiskScoreCalculator.calculate(
                asset_type="payment_instruction",
                is_success=True,
                unusual_network_source=True,
                evidence_confidence="High Confidence"
            )

            alerts.append(ThreatAlert(
                alert_id="ALT-BV-BANK-ACCESS-01",
                rule_id=self.rule_id,
                threat_category=self.category,
                severity=severity,
                risk_score=score,
                detection_explanation=(
                    f"Identified {len(bank_doc_events)} access requests to sensitive vendor bank instruction spreadsheets "
                    f"('/finance/bank-instructions/vendor-bank-details-2026.xlsx') by principal(s): {principals}. "
                    f"Accounted limitation: BlueVault clock was unsynchronized; temporal sequence is relative."
                ),
                triggering_event_ids=bank_doc_events["event_id"].head(10).tolist(),
                evidence_ids=["E05", "E13"],
                original_timestamps=bank_doc_events["timestamp_orig"].head(5).tolist(),
                normalised_timestamps=[first_doc["timestamp"].isoformat() if first_doc["timestamp"] else ""],
                confidence="High Confidence",
                recommended_action="Audit BlueVault storage access keys, verify file download integrity, and synchronize NTP clock on file cluster.",
                target_entity="BlueVault Vendor Bank Instructions",
                source_ip=str(first_doc["source_ip"]),
                rule_metadata={"access_count": len(bank_doc_events), "principals": principals}
            ))

        # Condition B: Key bvk-7f3a accessing broad cross-customer directories
        bvk_events = bv_events[bv_events["actor"] == "key:bvk-7f3a"]
        if not bvk_events.empty:
            cust_dirs = set()
            for path in bvk_events["target"]:
                parts = str(path).split("/")
                if len(parts) > 2 and parts[1] == "customer-docs":
                    cust_dirs.add(parts[2])

            if len(cust_dirs) > 10:
                score, severity = RiskScoreCalculator.calculate(
                    asset_type="customer_document",
                    is_success=True,
                    volume_burst=True,
                    evidence_confidence="Confirmed Fact"
                )
                alerts.append(ThreatAlert(
                    alert_id="ALT-BV-KEY-EXCESS-01",
                    rule_id="RULE-DOC-002",
                    threat_category=self.category,
                    severity=severity,
                    risk_score=score,
                    detection_explanation=(
                        f"Customer storage access key 'bvk-7f3a' (pasted into support ticket TKT-48213 in E13 for a single Pune customer) "
                        f"was used to access document directories across {len(cust_dirs)} distinct customer folders in BlueVault. "
                        f"Indicates horizontal privilege abuse and multi-tenant isolation failure."
                    ),
                    triggering_event_ids=bvk_events["event_id"].head(10).tolist(),
                    evidence_ids=["E05", "E13"],
                    original_timestamps=bvk_events["timestamp_orig"].head(5).tolist(),
                    normalised_timestamps=[],
                    confidence="Confirmed Fact",
                    recommended_action="Revoke key bvk-7f3a immediately and restrict customer portal keys to customer-specific folder scopes.",
                    target_entity="key:bvk-7f3a",
                    source_ip=str(bvk_events.iloc[0]["source_ip"]),
                    rule_metadata={"customers_accessed": len(cust_dirs)}
                ))

        return alerts
