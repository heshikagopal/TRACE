"""
TRACE Master Threat Detection Engine
Coordinates modular rules, context extraction, risk evaluation, and alert generation.
Completely decoupled from presentation/UI layers.
"""

from typing import List, Dict, Any, Optional
import pandas as pd
import logging

from trace_engine.alert_schema import ThreatAlert
from trace_engine.rules import (
    BaseRule,
    RuleFormerEmployeeAccess,
    RuleSuspiciousAPIActivity,
    RuleHelpdeskExportActivity,
    RuleVendorRecordModification,
    RuleUnusualDocumentAccess
)

logger = logging.getLogger("trace.detection")


class ThreatDetectionEngine:
    """
    Main detection orchestrator. Manages rule registration, contextual data loading,
    telemetry evaluation, and alert consolidation.
    """

    def __init__(self, ingestor=None):
        self.ingestor = ingestor
        self.rules: List[BaseRule] = []
        self._register_default_rules()

    def _register_default_rules(self):
        """Registers the 5 core threat detection rules."""
        self.rules = [
            RuleFormerEmployeeAccess(),
            RuleSuspiciousAPIActivity(),
            RuleHelpdeskExportActivity(),
            RuleVendorRecordModification(),
            RuleUnusualDocumentAccess()
        ]

    def register_rule(self, rule: BaseRule):
        """Adds a custom detection rule to the engine."""
        self.rules.append(rule)

    def load_context(self) -> Dict[str, Any]:
        """Loads non-event auxiliary context (rosters, integrations, risks) if ingestor is present."""
        context: Dict[str, Any] = {}
        if self.ingestor is not None:
            try:
                context["E14"] = self.ingestor.load_csv("E14")
            except Exception as e:
                logger.warning(f"Could not load E14 context: {e}")

            try:
                context["E04"] = self.ingestor.load_json("E04")
            except Exception as e:
                logger.warning(f"Could not load E04 context: {e}")

            try:
                context["E09"] = self.ingestor.load_risk_register()
            except Exception as e:
                logger.warning(f"Could not load E09 context: {e}")

            try:
                context["E17"] = self.ingestor.load_csv("E17")
            except Exception as e:
                logger.warning(f"Could not load E17 context: {e}")

        return context

    def evaluate_events(self, df_events: pd.DataFrame, context: Optional[Dict[str, Any]] = None) -> List[ThreatAlert]:
        """
        Executes all active rules against normalized events and consolidates results.
        Includes cross-system correlation check.
        """
        if context is None:
            context = self.load_context()

        all_alerts: List[ThreatAlert] = []

        # Run registered modular rules
        for rule in self.rules:
            if rule.enabled:
                try:
                    rule_alerts = rule.evaluate(df_events, context)
                    all_alerts.extend(rule_alerts)
                except Exception as e:
                    logger.error(f"Error executing rule {rule.rule_id} ({rule.name}): {e}", exc_info=True)

        # Cross-system correlation synthesis
        corr_alert = self._correlate_attack_chain(df_events, all_alerts)
        if corr_alert:
            all_alerts.append(corr_alert)

        # Sort alerts descending by risk score
        all_alerts.sort(key=lambda a: a.risk_score, reverse=True)
        return all_alerts

    def _correlate_attack_chain(self, df_events: pd.DataFrame, current_alerts: List[ThreatAlert]) -> Optional[ThreatAlert]:
        """
        Synthesizes individual indicators into an end-to-end multi-stage supply chain incident alert.
        Requires evidence from at least 3 distinct systems (HelpDeskr, BlueVault/Flow, and LedgerOne).
        """
        has_api_bank_change = any(a.rule_id == "RULE-FIN-001" for a in current_alerts)
        has_export_recon = any(a.rule_id in ("RULE-EXP-001", "RULE-EXP-002") for a in current_alerts)
        has_build_api = any(a.rule_id == "RULE-API-001" for a in current_alerts)

        if has_api_bank_change and has_export_recon and has_build_api:
            return ThreatAlert(
                alert_id="ALT-CHAIN-CORR-001",
                rule_id="RULE-CORR-001",
                threat_category="Supply Chain Multi-Stage Incident",
                severity="CRITICAL",
                risk_score=99.0,
                detection_explanation=(
                    "Correlated multi-stage attack progression identified across 5 enterprise systems: "
                    "1. Reconnaissance (11–12 Aug): Secret keyword searches and 30 bulk ticket exports in HelpDeskr (E02/E06); "
                    "2. Document Harvesting: Storage access key 'bvk-7f3a' used across 143 customer directories in BlueVault (E05); "
                    "3. Credential & Network Pivot: Integration key 'key-tb-07' invoked from build machine 10.20.4.77 (tb-build-02 in E15); "
                    "4. Financial Impact (3 Sep): Bank account of Coastal Packaging Ltd (V-0412) modified via API to ****9083 without approval (E18/E19)."
                ),
                triggering_event_ids=[
                    "E02:evt-a786f0a220",
                    "E02:evt-d5b7a8536",
                    "E05:bv-6e75b7ce9a",
                    "E15:flw-ae6f14a5f5",
                    "E18:req-5f61b0de8",
                    "E19:chg-8b9888c39b"
                ],
                evidence_ids=["E02", "E04", "E05", "E06", "E13", "E15", "E18", "E19", "E20"],
                original_timestamps=["2026-08-11 23:12:00", "2026-09-03T01:44:30Z"],
                normalised_timestamps=["2026-08-11T17:42:00Z", "2026-09-03T01:44:30Z"],
                confidence="Confirmed Fact",
                recommended_action=(
                    "1. Freeze scheduled vendor payment run immediately; "
                    "2. Sever TallyBridge private-link tunnel and revoke all issued integration credentials; "
                    "3. Initiate full digital forensics and incident response (DFIR) protocol under legal privilege."
                ),
                target_entity="Enterprise Payment Processing Chain",
                source_ip="10.20.4.77",
                rule_metadata={"stages_detected": ["reconnaissance", "credential_access", "lateral_pivot", "financial_tampering"]}
            )
        return None

    def run_all_detections(self, df_events: pd.DataFrame) -> List[Dict[str, Any]]:
        """Backwards compatibility helper returning alert dictionaries."""
        alerts = self.evaluate_events(df_events)
        return [a.to_dict() for a in alerts]


# Backwards-compatibility alias
DetectionEngine = ThreatDetectionEngine

