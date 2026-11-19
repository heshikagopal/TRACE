"""
Unit and Integration Tests for TRACE Cybersecurity Simulation Lab
Verifies Scenarios A through E, Confusion Matrix Calculations, and Held-Out Evaluation Suite.
"""

import unittest
from trace_engine.detection import ThreatDetectionEngine
from trace_engine.scenario_templates import ScenarioTemplateEngine, HELD_OUT_EVALUATION_SUITE
from trace_engine.simulation import SimulationLabRunner


class TestSimulationLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatDetectionEngine()
        cls.runner = SimulationLabRunner(cls.engine)

    def test_01_scenario_a_former_employee_positive_and_negative(self):
        """Verifies Scenario A triggers for post-term login, but stays silent for active employee."""
        # Positive: Terminated user logging in 15 days post-termination
        pos_events, pos_ctx = ScenarioTemplateEngine.generate_scenario_a_former_employee(
            is_terminated=True,
            login_success=True,
            days_after_termination=15
        )
        pos_res = self.runner.run_scenario(pos_events, context=pos_ctx)
        self.assertGreaterEqual(len(pos_res["alerts"]), 1)
        self.assertIn("RULE-AUTH-001", pos_res["detected_rules"])
        self.assertEqual(pos_res["true_positives"], 1)
        self.assertEqual(pos_res["false_positives"], 0)

        # Negative: Currently active employee
        neg_events, neg_ctx = ScenarioTemplateEngine.generate_scenario_a_former_employee(
            is_terminated=False,
            login_success=True,
            days_after_termination=0,
            username="sim.active.user"
        )
        neg_res = self.runner.run_scenario(neg_events, context=neg_ctx)
        self.assertEqual(len(neg_res["alerts"]), 0, "Active employee must NOT trigger alert")
        self.assertEqual(neg_res["true_negatives"], 1)

    def test_02_scenario_b_api_credential_misuse(self):
        """Verifies Scenario B flags build host 10.20.4.77, while normal sync pool 10.20.4.12 is benign."""
        # Positive: 10.20.4.77 build host
        pos_events, pos_ctx = ScenarioTemplateEngine.generate_scenario_b_api_activity(
            is_suspicious_caller=True,
            api_key_id="key-tb-07",
            caller_ip="10.20.4.77"
        )
        pos_res = self.runner.run_scenario(pos_events, context=pos_ctx)
        self.assertGreaterEqual(len(pos_res["alerts"]), 1)
        self.assertIn("RULE-API-001", pos_res["detected_rules"])

        # Negative: Standard sync pool IP 10.20.4.12 on /v2/shipments
        neg_events, neg_ctx = ScenarioTemplateEngine.generate_scenario_b_api_activity(
            is_suspicious_caller=False,
            is_sensitive_endpoint=False,
            api_key_id="key-tb-07",
            caller_ip="10.20.4.12",
            endpoint="/v2/shipments"
        )
        neg_res = self.runner.run_scenario(neg_events, context=neg_ctx)
        self.assertEqual(len(neg_res["alerts"]), 0, "Designated sync pool must NOT trigger alert")

    def test_03_scenario_c_vendor_modification(self):
        """Verifies Scenario C flags unapproved API changes, but accepts approved UI changes."""
        # Positive: Unapproved API change
        pos_events, pos_ctx = ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
            field_changed="bank_account",
            channel="API",
            has_approval_ref=False
        )
        pos_res = self.runner.run_scenario(pos_events, context=pos_ctx)
        self.assertGreaterEqual(len(pos_res["alerts"]), 1)
        self.assertIn("RULE-FIN-001", pos_res["detected_rules"])

        # Negative: Approved UI change with APR-SIM-9999
        neg_events, neg_ctx = ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
            field_changed="bank_account",
            channel="UI",
            has_approval_ref=True,
            approval_ref_val="APR-SIM-9999"
        )
        neg_res = self.runner.run_scenario(neg_events, context=neg_ctx)
        self.assertEqual(len(neg_res["alerts"]), 0, "Approved UI change must NOT trigger alert")

    def test_04_scenario_d_export_activity(self):
        """Verifies Scenario D flags burst exports and keyword searches."""
        # Positive: 10 bulk exports in 30 minutes + keyword reconnaissance
        pos_events, pos_ctx = ScenarioTemplateEngine.generate_scenario_d_export_activity(
            is_burst=True,
            include_recon_searches=True,
            export_count=10
        )
        pos_res = self.runner.run_scenario(pos_events, context=pos_ctx)
        self.assertGreaterEqual(len(pos_res["alerts"]), 2)
        self.assertIn("RULE-EXP-001", pos_res["detected_rules"])
        self.assertIn("RULE-EXP-002", pos_res["detected_rules"])

    def test_05_scenario_e_multi_stage_progression(self):
        """Verifies Scenario E end-to-end multi-stage activity synthesizes RULE-CORR-001 alert."""
        events, ctx = ScenarioTemplateEngine.generate_scenario_e_multi_stage(
            include_former_employee=True,
            include_recon=True,
            include_api_pivot=True,
            include_vendor_tamper=True
        )
        res = self.runner.run_scenario(events, context=ctx)
        self.assertIn("RULE-CORR-001", res["detected_rules"], "Multi-stage progression must trigger RULE-CORR-001")
        self.assertIn("RULE-FIN-001", res["detected_rules"])
        self.assertIn("RULE-AUTH-001", res["detected_rules"])

    def test_06_held_out_evaluation_battery(self):
        """Executes all 6 held-out variation tests and verifies perfect accuracy (Precision=1.0, Recall=1.0)."""
        suite_res = self.runner.run_held_out_evaluation(HELD_OUT_EVALUATION_SUITE)
        self.assertTrue(suite_res["all_passed"], f"Held-out test failures: {suite_res['test_details']}")
        self.assertEqual(suite_res["tests_passed"], suite_res["tests_total"])
        self.assertEqual(suite_res["aggregate_confusion"]["FP"], 0, "Must have zero false positives on lookalikes")
        self.assertEqual(suite_res["aggregate_metrics"]["precision"], 1.0)
        self.assertEqual(suite_res["aggregate_metrics"]["recall"], 1.0)

    def test_07_synthetic_record_labeling_and_safety(self):
        """Verifies all synthetic records are explicitly tagged as SIMULATED to guarantee zero evidence pollution."""
        events, _ = ScenarioTemplateEngine.generate_scenario_e_multi_stage()
        for evt in events:
            self.assertTrue(evt["is_synthetic"])
            self.assertTrue(evt["simulation_id"].startswith("SIM-"))
            self.assertEqual(evt["raw_record"]["data_source"], "SIMULATED_TEST_LAB")


if __name__ == "__main__":
    unittest.main()
