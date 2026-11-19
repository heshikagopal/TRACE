"""
Unit and Integration Test Suite for TRACE Threat Detection Engine
Tests Positive Detections, Negative Detections, Missing Fields, Invalid Timestamps,
Duplicate Events, and Legitimate Activity Resembling Suspicious Behavior.
"""

import unittest
from datetime import datetime, timezone
import pandas as pd

from trace_engine.alert_schema import ThreatAlert
from trace_engine.risk_scoring import RiskScoreCalculator
from trace_engine.ingestion import EvidenceIngestor
from trace_engine.normalisation import parse_timestamp_safe, EventNormaliser, load_and_normalise_all
from trace_engine.rules import (
    RuleFormerEmployeeAccess,
    RuleSuspiciousAPIActivity,
    RuleHelpdeskExportActivity,
    RuleVendorRecordModification,
    RuleUnusualDocumentAccess
)
from trace_engine.detection import ThreatDetectionEngine


class TestDetectionEngineComprehensive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ingestor = EvidenceIngestor("data/original")
        cls.engine = ThreatDetectionEngine(cls.ingestor)
        cls.context = cls.engine.load_context()
        cls.df_events = load_and_normalise_all(cls.ingestor)

    # -------------------------------------------------------------------------
    # 1. POSITIVE DETECTION TESTS (Real Case Evidence)
    # -------------------------------------------------------------------------
    def test_01_positive_detection_all_rules(self):
        """Verifies that all 5 detection rules produce positive detections on actual case evidence."""
        alerts = self.engine.evaluate_events(self.df_events, self.context)
        self.assertGreater(len(alerts), 0, "Engine must produce alerts on actual case telemetry")

        triggered_rule_ids = set(a.rule_id for a in alerts)
        
        # Rule 1: Former employee login
        self.assertIn("RULE-AUTH-001", triggered_rule_ids)
        auth_alerts = [a for a in alerts if a.rule_id == "RULE-AUTH-001"]
        self.assertIn("r.menon", auth_alerts[0].target_entity)
        self.assertTrue(auth_alerts[0].rule_metadata.get("is_success"))

        # Rule 2: Suspicious API activity
        self.assertIn("RULE-API-001", triggered_rule_ids)
        api_alerts = [a for a in alerts if a.rule_id == "RULE-API-001"]
        self.assertEqual(api_alerts[0].source_ip, "10.20.4.77")

        # Rule 3: Helpdesk exports & reconnaissance
        self.assertIn("RULE-EXP-001", triggered_rule_ids)
        self.assertIn("RULE-EXP-002", triggered_rule_ids)

        # Rule 4: Vendor bank record modification
        self.assertIn("RULE-FIN-001", triggered_rule_ids)
        fin_alerts = [a for a in alerts if a.rule_id == "RULE-FIN-001"]
        self.assertIn("Coastal Packaging", fin_alerts[0].target_entity)

        # Rule 5: Unusual document access
        self.assertIn("RULE-DOC-001", triggered_rule_ids)
        self.assertIn("RULE-DOC-002", triggered_rule_ids)

        # Multi-stage correlation
        self.assertIn("RULE-CORR-001", triggered_rule_ids)

    # -------------------------------------------------------------------------
    # 2. NEGATIVE DETECTION TESTS (Ensure No False Positives)
    # -------------------------------------------------------------------------
    def test_02_negative_detection_active_employees(self):
        """Verify active staff logins do NOT trigger RuleFormerEmployeeAccess."""
        rule = RuleFormerEmployeeAccess()
        # Create synthetic event for active user 'f.dsouza' (Senior Accountant)
        active_login_event = pd.DataFrame([{
            "event_id": "TEST:sso-001",
            "original_event_id": "sso-001",
            "timestamp": datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc),
            "timestamp_orig": "2026-08-10T09:00:00+00:00",
            "timezone_assumption": "UTC",
            "source_evidence_id": "E03",
            "system": "SSO",
            "actor": "f.dsouza",
            "actor_type": "user",
            "action": "sso.signin",
            "target": "SSO_Portal",
            "source_ip": "172.16.8.42",
            "result": "success",
            "details": {}
        }])

        alerts = rule.evaluate(active_login_event, self.context)
        self.assertEqual(len(alerts), 0, "Active employee login must NOT trigger post-termination alert")

    def test_03_negative_detection_normal_sync_api(self):
        """Verify normal sync API requests from designated pool do NOT trigger RuleSuspiciousAPIActivity."""
        rule = RuleSuspiciousAPIActivity()
        # Normal sync request from 10.20.4.12
        normal_sync_event = pd.DataFrame([{
            "event_id": "TEST:req-001",
            "original_event_id": "req-001",
            "timestamp": datetime(2026, 8, 5, 2, 0, tzinfo=timezone.utc),
            "timestamp_orig": "2026-08-05T02:00:00Z",
            "timezone_assumption": "UTC",
            "source_evidence_id": "E01",
            "system": "LedgerOne",
            "actor": "key-tb-07",
            "actor_type": "integration_key",
            "action": "api.get",
            "target": "/v2/shipments",
            "source_ip": "10.20.4.12",
            "result": "200",
            "details": {"method": "GET"}
        }])

        alerts = rule.evaluate(normal_sync_event, self.context)
        self.assertEqual(len(alerts), 0, "Normal sync from 10.20.4.12 on standard endpoint must NOT trigger alert")

    # -------------------------------------------------------------------------
    # 3. MISSING OPTIONAL FIELDS TESTS
    # -------------------------------------------------------------------------
    def test_04_missing_optional_fields_resilience(self):
        """Verify rules handle NaN, None, or absent optional fields without raising exceptions."""
        rule_fin = RuleVendorRecordModification()
        event_with_nans = pd.DataFrame([{
            "event_id": "TEST:chg-nan",
            "original_event_id": "chg-nan",
            "timestamp": None,
            "timestamp_orig": "",
            "timezone_assumption": "Missing",
            "source_evidence_id": "E19",
            "system": "LedgerOne_VendorMaster",
            "actor": "test_user",
            "actor_type": "user",
            "action": "vendor.change.contact_phone",
            "target": "V-001",
            "source_ip": None,
            "result": "applied",
            "details": {
                "field": "contact_phone",
                "channel": None,
                "approval_ref": None,
                "old_value": None,
                "new_value": None
            }
        }])

        alerts = rule_fin.evaluate(event_with_nans, self.context)
        self.assertEqual(len(alerts), 0, "Benign field change with null values must be handled cleanly without alert")

    # -------------------------------------------------------------------------
    # 4. INVALID / UNPARSEABLE TIMESTAMPS TESTS
    # -------------------------------------------------------------------------
    def test_05_invalid_timestamp_handling(self):
        """Verify parse_timestamp_safe handles unparseable, malformed, or blank timestamps safely."""
        # Null string
        dt, orig, tz_assump = parse_timestamp_safe("", "E01")
        self.assertIsNone(dt)
        self.assertEqual(orig, "")

        # Malformed text
        dt2, orig2, tz_assump2 = parse_timestamp_safe("NOT_A_TIMESTAMP_STRING", "E02")
        self.assertIsNone(dt2)
        self.assertEqual(orig2, "NOT_A_TIMESTAMP_STRING")
        self.assertIn("Unparseable", tz_assump2)

    # -------------------------------------------------------------------------
    # 5. DUPLICATE EVENTS TESTS
    # -------------------------------------------------------------------------
    def test_06_duplicate_events_handling(self):
        """Verify duplicate events are ingested without crashing or corrupting engine state."""
        df_sub = self.df_events.head(50)
        df_duplicated = pd.concat([df_sub, df_sub], ignore_index=True)
        self.assertEqual(len(df_duplicated), 100)

        # Engine evaluation runs cleanly over duplicates
        alerts = self.engine.evaluate_events(df_duplicated, self.context)
        self.assertIsInstance(alerts, list)

    # -------------------------------------------------------------------------
    # 6. LEGITIMATE ACTIVITY RESEMBLING SUSPICIOUS BEHAVIOR
    # -------------------------------------------------------------------------
    def test_07_legitimate_approved_bank_change(self):
        """
        Verify that an authorized vendor bank detail change made via UI
        with a valid approval reference does NOT trigger an alert.
        """
        rule = RuleVendorRecordModification()
        legitimate_change = pd.DataFrame([{
            "event_id": "TEST:chg-valid",
            "original_event_id": "chg-valid",
            "timestamp": datetime(2026, 6, 4, 6, 12, tzinfo=timezone.utc),
            "timestamp_orig": "2026-06-04T06:12:43Z",
            "timezone_assumption": "UTC",
            "source_evidence_id": "E19",
            "system": "LedgerOne_VendorMaster",
            "actor": "n.ansari",
            "actor_type": "user",
            "action": "vendor.change.bank_account",
            "target": "V-0126 (Surya Logistics)",
            "source_ip": "172.16.8.28",
            "result": "applied",
            "details": {
                "vendor_id": "V-0126",
                "vendor_name": "Surya Logistics Supply 126",
                "field": "bank_account",
                "old_value": "****0581",
                "new_value": "****0067",
                "channel": "UI",
                "approval_ref": "APR-1108",    # Valid dual authorization reference!
                "request_id": ""
            }
        }])

        alerts = rule.evaluate(legitimate_change, self.context)
        self.assertEqual(len(alerts), 0, "Approved bank account change with APR-1108 must NOT trigger an alert")

    def test_08_legitimate_tuesday_scheduled_export(self):
        """
        Verify that normal single scheduled weekly ticket exports on Tuesday
        do NOT trigger the abnormal bulk export burst rule.
        """
        rule = RuleHelpdeskExportActivity(export_burst_threshold=5)
        # Tuesday 14:40 single export
        tuesday_export = pd.DataFrame([{
            "event_id": "TEST:evt-export-tues",
            "original_event_id": "evt-export-tues",
            "timestamp": datetime(2026, 6, 9, 9, 10, tzinfo=timezone.utc),
            "timestamp_orig": "09/06/2026 14:40:00",
            "timezone_assumption": "IST",
            "source_evidence_id": "E02",
            "system": "HelpDeskr",
            "actor": "s.iyer",
            "actor_type": "user",
            "action": "ticket.export",
            "target": "EXPORT-001",
            "source_ip": "172.16.8.15",
            "result": "ok",
            "details": {}
        }])

        alerts = rule.evaluate(tuesday_export, self.context)
        self.assertEqual(len(alerts), 0, "Scheduled Tuesday export must NOT trigger abnormal burst alert")


if __name__ == "__main__":
    unittest.main()
