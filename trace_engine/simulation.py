"""
TRACE Simulation Runner & Performance Evaluator
Executes synthetic cybersecurity scenarios through the standard ThreatDetectionEngine.
Calculates confusion metrics, precision, recall, and detection accuracy without mock shortcuts.
"""

from typing import List, Dict, Any, Optional
import pandas as pd
import logging

from trace_engine.detection import ThreatDetectionEngine
from trace_engine.alert_schema import ThreatAlert
from trace_engine.scenario_templates import ScenarioTemplateEngine, HELD_OUT_EVALUATION_SUITE

logger = logging.getLogger("trace.simulation")


class SimulationLabRunner:
    """Orchestrates simulation execution, evaluation, and confusion metric computation."""

    def __init__(self, engine: Optional[ThreatDetectionEngine] = None):
        self.engine = engine or ThreatDetectionEngine()

    def run_scenario(
        self,
        events: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
        expected_rules: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Executes a stream of synthetic events through the production ThreatDetectionEngine.
        Compares raised alerts against expected detection signatures.
        """
        if not events:
            return {
                "events_count": 0,
                "alerts": [],
                "expected_rules": expected_rules or [],
                "detected_rules": [],
                "true_positives": 0,
                "false_positives": 0,
                "false_negatives": 0,
                "true_negatives": 1,
                "metrics": {"precision": 1.0, "recall": 1.0, "f1": 1.0}
            }

        df_synthetic = pd.DataFrame(events)
        raised_alerts: List[ThreatAlert] = self.engine.evaluate_events(df_synthetic, context=context)

        detected_rule_ids = [a.rule_id for a in raised_alerts]
        unique_detected = set(detected_rule_ids)

        # Expected rules from parameter or derived from event annotations
        if expected_rules is None:
            expected_set = set()
            for e in events:
                exp = e.get("expected_classification", "BENIGN")
                if exp != "BENIGN":
                    expected_set.add(exp)
            expected_rules = list(expected_set)
        else:
            expected_set = set(expected_rules)

        # Confusion metrics calculation
        tp_rules = list(unique_detected.intersection(expected_set))
        fp_rules = list(unique_detected.difference(expected_set))
        fn_rules = list(expected_set.difference(unique_detected))

        tp = len(tp_rules)
        fp = len(fp_rules)
        fn = len(fn_rules)
        # TN represents expected benign events that raised no alert
        is_clean_benign = (len(expected_set) == 0 and len(unique_detected) == 0)
        tn = 1 if is_clean_benign else 0

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fp == 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if fn == 0 else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "events_count": len(events),
            "events": events,
            "alerts": [a.to_dict() for a in raised_alerts],
            "expected_rules": expected_rules,
            "detected_rules": detected_rule_ids,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "tp_rules": tp_rules,
            "fp_rules": fp_rules,
            "fn_rules": fn_rules,
            "metrics": {
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1_score": round(f1, 3),
                "false_positive_rate": round(fpr, 3),
                "detection_rate": round(recall, 3)
            }
        }

    def run_held_out_evaluation(self, suite: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Runs the full battery of held-out evaluation test cases to assess generalization
        against variations (different IPs, re-ordered sequences, approved lookalikes).
        """
        suite = suite or HELD_OUT_EVALUATION_SUITE
        test_results = []

        total_tp = 0
        total_fp = 0
        total_fn = 0
        total_tn = 0

        for item in suite:
            name = item["test_name"]
            desc = item["description"]
            generator = item["generator"]
            expected_count = item["expected_alert_count"]
            exp_rule = item.get("expected_rule")

            evs, ctx = generator()
            exp_rules = [exp_rule] if exp_rule else []

            res = self.run_scenario(evs, context=ctx, expected_rules=exp_rules)
            actual_count = len(res["alerts"])
            passed = (actual_count == expected_count)

            total_tp += res["true_positives"]
            total_fp += res["false_positives"]
            total_fn += res["false_negatives"]
            total_tn += res["true_negatives"]

            test_results.append({
                "test_name": name,
                "description": desc,
                "passed": passed,
                "expected_alert_count": expected_count,
                "actual_alert_count": actual_count,
                "expected_rules": exp_rules,
                "detected_rules": res["detected_rules"],
                "alerts_raised": [a["alert_id"] for a in res["alerts"]]
            })

        overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
        overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
        overall_f1 = (2 * overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0.0

        all_passed = all(t["passed"] for t in test_results)

        return {
            "all_passed": all_passed,
            "tests_total": len(test_results),
            "tests_passed": sum(1 for t in test_results if t["passed"]),
            "aggregate_confusion": {
                "TP": total_tp,
                "FP": total_fp,
                "FN": total_fn,
                "TN": total_tn
            },
            "aggregate_metrics": {
                "precision": round(overall_precision, 3),
                "recall": round(overall_recall, 3),
                "f1_score": round(overall_f1, 3)
            },
            "test_details": test_results
        }
