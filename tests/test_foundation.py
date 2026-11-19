"""
Unit and Integration Tests for TRACE Foundation
Verifies Ingestion, Normalisation, and Initial Detection Rules against real CRIMEATHON'26 evidence.
"""

import unittest
import os
import pandas as pd
from trace_engine.ingestion import EvidenceIngestor, EVIDENCE_CATALOG
from trace_engine.normalisation import EventNormaliser, load_and_normalise_all, parse_timestamp_safe
from trace_engine.detection import DetectionEngine


class TestTRACEFoundation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = "data/original"
        cls.ingestor = EvidenceIngestor(cls.data_dir)

    def test_01_evidence_inventory_completeness(self):
        """Verify all 20 evidence files (E01-E20) are inventoried and exist."""
        inventory = self.ingestor.get_inventory()
        self.assertEqual(len(inventory), 20, "Catalog must contain exactly 20 evidence entries")
        
        missing = [item["evidence_id"] for item in inventory if not item["exists"]]
        self.assertEqual(len(missing), 0, f"Missing evidence files: {missing}")

    def test_02_source_parsers(self):
        """Verify parsing across all 4 formats: CSV, JSON, Excel, PDF."""
        # 1. CSV (E01)
        df_e01 = self.ingestor.load_csv("E01")
        self.assertFalse(df_e01.empty)
        self.assertIn("caller_ip", df_e01.columns)

        # 2. JSON (E04)
        e04 = self.ingestor.load_json("E04")
        self.assertIn("integrations", e04)
        self.assertGreaterEqual(len(e04["integrations"]), 1)

        # 3. Excel (E09)
        df_e09 = self.ingestor.load_risk_register()
        self.assertFalse(df_e09.empty)
        self.assertIn("Risk ID", df_e09.columns)

        # 4. PDF (E06)
        e06 = self.ingestor.load_pdf("E06")
        self.assertEqual(e06["total_pages"], 2)
        self.assertIn("Bulk Export", e06["pages"][0]["text"])

    def test_03_timestamp_normalisation_and_preservation(self):
        """Verify timestamp handling across UTC, IST local time, and Unix Epoch."""
        # A. UTC ISO timestamp (E01)
        dt_utc, orig, tz_assump = parse_timestamp_safe("2026-06-03T00:31:22Z", "E01")
        self.assertIsNotNone(dt_utc)
        self.assertEqual(orig, "2026-06-03T00:31:22Z")
        self.assertIn("UTC", tz_assump)

        # B. IST Local timestamp (E02): "03/06/2026 07:30:58" should convert to 02:00:58 UTC
        dt_local, orig_local, tz_assump_local = parse_timestamp_safe("03/06/2026 07:30:58", "E02")
        self.assertIsNotNone(dt_local)
        self.assertEqual(dt_local.hour, 2)
        self.assertEqual(dt_local.minute, 0)
        self.assertEqual(dt_local.second, 58)
        self.assertIn("IST", tz_assump_local)

        # C. Unix epoch (E05)
        dt_epoch, orig_epoch, tz_assump_epoch = parse_timestamp_safe(1780456174, "E05")
        self.assertIsNotNone(dt_epoch)
        self.assertIn("Unsynchronised BlueVault clock", tz_assump_epoch)

    def test_04_full_normalisation_stream(self):
        """Verify full event pipeline ingestion and schema consistency."""
        df_events = load_and_normalise_all(self.ingestor)
        self.assertFalse(df_events.empty)
        
        required_cols = [
            "event_id", "original_event_id", "timestamp", "timestamp_orig",
            "timezone_assumption", "source_evidence_id", "system",
            "actor", "actor_type", "action", "target", "source_ip", "result", "details", "raw_record"
        ]
        for col in required_cols:
            self.assertIn(col, df_events.columns, f"Normalized events missing column: {col}")
        
        print(f"Total normalised events ingested: {len(df_events):,}")

    def test_05_detection_rules_against_case_evidence(self):
        """Verify that all initial detection rules accurately fire on actual case evidence."""
        df_events = load_and_normalise_all(self.ingestor)
        engine = DetectionEngine(self.ingestor)
        alerts = engine.run_all_detections(df_events)

        self.assertGreater(len(alerts), 0, "Detection engine must produce alerts on supplied case evidence")
        
        rules_triggered = set(a["triggered_rule"].split(":")[0] for a in alerts)
        print("Rules triggered:", rules_triggered)

        # 1. Former employee rule
        auth_alerts = [a for a in alerts if "RULE-AUTH-001" in a["triggered_rule"]]
        self.assertTrue(len(auth_alerts) >= 1, "Must detect former employee (r.menon) post-termination login")
        self.assertIn("r.menon", auth_alerts[0]["target_entity"])

        # 2. Suspicious API rule
        api_alerts = [a for a in alerts if "RULE-API-001" in a["triggered_rule"]]
        self.assertTrue(len(api_alerts) >= 1, "Must detect build host 10.20.4.77 using key-tb-07 on sensitive endpoints")

        # 3. HelpDeskr bulk exports & credential recon
        hd_alerts = [a for a in alerts if "RULE-EXP" in a["triggered_rule"]]
        self.assertTrue(len(hd_alerts) >= 1, "Must detect bulk export burst / credential searches in HelpDeskr")

        # 4. Vendor bank change
        fin_alerts = [a for a in alerts if "RULE-FIN-001" in a["triggered_rule"]]
        self.assertTrue(len(fin_alerts) >= 1, "Must detect unauthorized API modification of vendor bank details")
        self.assertIn("Coastal Packaging", fin_alerts[0]["target_entity"])

        # 5. Cross system chain
        chain_alerts = [a for a in alerts if "RULE-CORR-001" in a["triggered_rule"]]
        self.assertEqual(len(chain_alerts), 1, "Must produce end-to-end multi-stage correlation alert")

        # Validate alert schema completeness
        for a in alerts:
            self.assertTrue(a["alert_id"])
            self.assertTrue(a["detection_category"])
            self.assertIn(a["severity"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            self.assertTrue(0 <= a["risk_score"] <= 100)
            self.assertTrue(a["explanation"])
            self.assertTrue(a["triggered_rule"])
            self.assertTrue(len(a["related_event_ids"]) > 0)
            self.assertTrue(len(a["original_evidence_ids"]) > 0)
            self.assertTrue(a["recommended_action"])


if __name__ == "__main__":
    unittest.main()
