"""
Automated Test Suite for TRACE Defensive Performance Evaluation Engine
Validates metric calculations, safe zero-denominator handling, evaluation modes,
robustness stress testing, and evaluation reproducibility.
"""

import unittest
import json
from typing import List

from trace_engine.evaluation import (
    DefensiveEvaluationEngine,
    TestCaseResult,
    calculate_metrics,
    build_evaluation_dataset
)


class TestEvaluationMetricsCalculation(unittest.TestCase):
    """Validates mathematical correctness of diagnostic metric computations."""

    def test_perfect_score_metrics(self):
        """Verifies calculation when engine achieves 100% precision and recall."""
        results = [
            TestCaseResult(
                test_id=f"TP-{i}", scenario="Attack", mode="test", ground_truth=1,
                detection_result=1, classification="TP", expected_alert="RULE-01",
                actual_alert="RULE-01", result="Correct", explanation="", execution_time_ms=5.0,
                events_count=1, alerts_count=1
            ) for i in range(10)
        ] + [
            TestCaseResult(
                test_id=f"TN-{i}", scenario="Benign", mode="test", ground_truth=0,
                detection_result=0, classification="TN", expected_alert="",
                actual_alert="", result="Correct", explanation="", execution_time_ms=4.0,
                events_count=1, alerts_count=0
            ) for i in range(10)
        ]

        metrics = calculate_metrics(results)
        self.assertEqual(metrics.total_cases, 20)
        self.assertEqual(metrics.true_positives, 10)
        self.assertEqual(metrics.false_positives, 0)
        self.assertEqual(metrics.true_negatives, 10)
        self.assertEqual(metrics.false_negatives, 0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.f1_score, 1.0)
        self.assertEqual(metrics.false_positive_rate, 0.0)
        self.assertEqual(metrics.detection_rate, 1.0)

    def test_imperfect_score_metrics(self):
        """Verifies calculation with known error rates (TP=8, FP=2, TN=8, FN=2)."""
        results = []
        # 8 TP
        for i in range(8):
            results.append(TestCaseResult(
                test_id=f"TP-{i}", scenario="Attack", mode="test", ground_truth=1,
                detection_result=1, classification="TP", expected_alert="RULE-01",
                actual_alert="RULE-01", result="", explanation="", execution_time_ms=5.0,
                events_count=1, alerts_count=1
            ))
        # 2 FP
        for i in range(2):
            results.append(TestCaseResult(
                test_id=f"FP-{i}", scenario="Benign", mode="test", ground_truth=0,
                detection_result=1, classification="FP", expected_alert="",
                actual_alert="RULE-01", result="", explanation="", execution_time_ms=5.0,
                events_count=1, alerts_count=1
            ))
        # 8 TN
        for i in range(8):
            results.append(TestCaseResult(
                test_id=f"TN-{i}", scenario="Benign", mode="test", ground_truth=0,
                detection_result=0, classification="TN", expected_alert="",
                actual_alert="", result="", explanation="", execution_time_ms=4.0,
                events_count=1, alerts_count=0
            ))
        # 2 FN
        for i in range(2):
            results.append(TestCaseResult(
                test_id=f"FN-{i}", scenario="Attack", mode="test", ground_truth=1,
                detection_result=0, classification="FN", expected_alert="RULE-01",
                actual_alert="", result="", explanation="", execution_time_ms=4.0,
                events_count=1, alerts_count=0
            ))

        metrics = calculate_metrics(results)
        self.assertEqual(metrics.total_cases, 20)
        # Precision: 8 / (8 + 2) = 0.8
        self.assertEqual(metrics.precision, 0.8)
        # Recall: 8 / (8 + 2) = 0.8
        self.assertEqual(metrics.recall, 0.8)
        # F1: 2 * (0.8 * 0.8) / 1.6 = 0.8
        self.assertEqual(metrics.f1_score, 0.8)
        # FPR: 2 / (2 + 8) = 0.2
        self.assertEqual(metrics.false_positive_rate, 0.2)

    def test_safe_zero_denominator_handling(self):
        """Verifies that undefined zero-division cases do not crash and produce explanatory notes."""
        # 1. No positive detections (TP=0, FP=0)
        results_no_pos = [
            TestCaseResult(
                test_id="TN-01", scenario="Benign", mode="test", ground_truth=0,
                detection_result=0, classification="TN", expected_alert="",
                actual_alert="", result="", explanation="", execution_time_ms=3.0,
                events_count=1, alerts_count=0
            )
        ]
        m1 = calculate_metrics(results_no_pos)
        self.assertIsNone(m1.precision)
        self.assertIn("Undefined", m1.precision_note)
        self.assertIsNone(m1.recall)
        self.assertIn("Undefined", m1.recall_note)
        self.assertIsNone(m1.f1_score)
        self.assertIn("Undefined", m1.f1_note)
        self.assertEqual(m1.false_positive_rate, 0.0)

        # 2. No benign cases (TN=0, FP=0) -> FPR denominator is zero
        results_no_neg = [
            TestCaseResult(
                test_id="TP-01", scenario="Attack", mode="test", ground_truth=1,
                detection_result=1, classification="TP", expected_alert="R1",
                actual_alert="R1", result="", explanation="", execution_time_ms=3.0,
                events_count=1, alerts_count=1
            )
        ]
        m2 = calculate_metrics(results_no_neg)
        self.assertEqual(m2.precision, 1.0)
        self.assertEqual(m2.recall, 1.0)
        self.assertIsNone(m2.false_positive_rate)
        self.assertIn("Undefined", m2.fpr_note)


class TestEvaluationModesAndExecution(unittest.TestCase):
    """Validates the execution of individual evaluation modes and full suites."""

    @classmethod
    def setUpClass(cls):
        cls.engine = DefensiveEvaluationEngine()

    def test_ground_truth_dataset_integrity(self):
        """Verifies that all 34 benchmark test cases are well-formed and clearly labeled."""
        cases = build_evaluation_dataset()
        self.assertGreaterEqual(len(cases), 30)

        for c in cases:
            self.assertIn(c.ground_truth, (0, 1), f"Invalid GT on {c.test_id}")
            self.assertIn(c.mode, ("rule_validation", "scenario_validation", "unseen_variation", "robustness"))
            self.assertTrue(len(c.test_id) > 0)
            self.assertTrue(callable(c.generator_fn))

    def test_mode_a_rule_validation(self):
        """Tests Mode A execution across all 5 core threat rules."""
        res = self.engine.run_rule_validation()
        self.assertEqual(res.mode, "Rule Validation (Mode A)")
        self.assertGreaterEqual(len(res.case_results), 14)
        self.assertGreaterEqual(res.metrics.recall, 0.95)
        self.assertEqual(res.metrics.false_positives, 0)

    def test_mode_b_scenario_validation(self):
        """Tests Mode B execution through full detection and correlation pipeline."""
        res = self.engine.run_scenario_validation()
        self.assertEqual(res.mode, "Scenario Validation (Mode B)")
        self.assertGreaterEqual(len(res.case_results), 5)
        self.assertEqual(res.metrics.true_positives, 5)
        self.assertEqual(res.metrics.true_negatives, 1)
        self.assertEqual(res.metrics.false_positives, 0)
        self.assertEqual(res.metrics.false_negatives, 0)

    def test_mode_c_unseen_variation_testing(self):
        """Tests Mode C execution for generalization against held-out edge cases."""
        res = self.engine.run_unseen_variation_testing()
        self.assertEqual(res.mode, "Unseen Variation Testing (Mode C)")
        self.assertGreaterEqual(len(res.case_results), 6)
        self.assertEqual(res.metrics.false_positives, 0)
        self.assertEqual(res.metrics.false_negatives, 0)

    def test_mode_d_robustness_stress_testing(self):
        """Tests Mode D across all 8 required robustness dimensions."""
        res = self.engine.run_robustness_testing()
        self.assertEqual(res.mode, "Robustness Stress Testing (Mode D)")
        
        required_types = [
            "missing_optional_fields",
            "timestamp_variation",
            "different_ips",
            "changed_sequence",
            "duplicate_records",
            "legitimate_vendor_change",
            "normal_api_activity",
            "unrelated_events"
        ]
        for r_type in required_types:
            self.assertIn(r_type, res.robustness_breakdown, f"Missing robustness dimension: {r_type}")
            stats = res.robustness_breakdown[r_type]
            self.assertEqual(stats["failed"], 0, f"Robustness failure in {r_type}")

    def test_report_generation(self):
        """Verifies report generation output for both Markdown and JSON formats."""
        res = self.engine.run_all()

        # Markdown Report
        md_report = self.engine.generate_report(res, format="markdown")
        self.assertIn("# TRACE Defensive Performance Evaluation Report", md_report)
        self.assertIn("Confusion Matrix", md_report)
        self.assertIn("Strict Evidence-Grounding vs. Synthetic Separation", md_report)
        self.assertIn("Robustness Stress-Testing Breakdown", md_report)
        self.assertIn("Engine Limitations", md_report)

        # JSON Report
        json_report = self.engine.generate_report(res, format="json")
        parsed = json.loads(json_report)
        self.assertIn("metrics", parsed)
        self.assertIn("case_results", parsed)
        self.assertIn("robustness_breakdown", parsed)
        self.assertEqual(parsed["metrics"]["true_positives"], 22)
        self.assertEqual(parsed["metrics"]["false_positives"], 0)

    def test_evaluation_reproducibility(self):
        """Verifies that running evaluation repeatedly produces identical deterministic outcomes."""
        res1 = self.engine.run_all()
        res2 = self.engine.run_all()

        self.assertEqual(res1.metrics.true_positives, res2.metrics.true_positives)
        self.assertEqual(res1.metrics.false_positives, res2.metrics.false_positives)
        self.assertEqual(res1.metrics.true_negatives, res2.metrics.true_negatives)
        self.assertEqual(res1.metrics.false_negatives, res2.metrics.false_negatives)
        self.assertEqual(res1.metrics.precision, res2.metrics.precision)
        self.assertEqual(res1.metrics.recall, res2.metrics.recall)


if __name__ == "__main__":
    unittest.main()
