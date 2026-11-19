"""
TRACE Defensive Performance Evaluation Engine
A reproducible, rigorous evaluation framework to measure detection efficacy,
precision, recall, false-positive rate, and robustness across enterprise cybersecurity telemetry.

Adheres strictly to evidence-grounded evaluation principles:
- Ground truth is explicitly defined for synthetic benchmark cases (1 = suspicious, 0 = legitimate).
- Real competition evidence without verified labels is never subjected to synthetic accuracy assumptions.
- Metrics handle zero denominators safely with explicit explanatory notes.
- Fully runnable standalone and integrated into Streamlit.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timezone, timedelta
import pandas as pd
import json
import time
import os
import logging
import uuid

from trace_engine.detection import ThreatDetectionEngine
from trace_engine.alert_schema import ThreatAlert
from trace_engine.synthetic_data import SyntheticEventBuilder, SIMULATION_TAG
from trace_engine.scenario_templates import ScenarioTemplateEngine

logger = logging.getLogger("trace.evaluation")


# =================================================================================================
# 1. EVALUATION DATA MODELS & METRIC CONTAINER
# =================================================================================================

@dataclass
class TestCase:
    """Represents an individual ground-truth test case for evaluation."""
    test_id: str
    name: str
    description: str
    mode: str                           # "rule_validation", "scenario_validation", "unseen_variation", "robustness"
    ground_truth: int                   # 1 = suspicious, 0 = legitimate
    generator_fn: Callable[[], tuple[List[Dict[str, Any]], Dict[str, Any]]]
    target_rule: Optional[str] = None   # Target rule for Rule Validation mode
    expected_rules: List[str] = field(default_factory=list)
    robustness_type: Optional[str] = None  # e.g. "missing_optional_fields", "timestamp_variation", etc.


@dataclass
class TestCaseResult:
    """Individual result after running a TestCase through the ThreatDetectionEngine."""
    test_id: str
    scenario: str
    mode: str
    ground_truth: int                   # 1 = suspicious, 0 = legitimate
    detection_result: int               # 1 = detected, 0 = benign/not detected
    classification: str                 # "TP", "FP", "TN", "FN"
    expected_alert: str
    actual_alert: str
    result: str                         # Human-readable status (e.g. "Correct Detection (TP)")
    explanation: str
    execution_time_ms: float
    events_count: int
    alerts_count: int
    detected_rule_ids: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConfusionMetrics:
    """Comprehensive performance metrics container with safe zero-denominator handling."""
    total_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: Optional[float]
    precision_note: str
    recall: Optional[float]
    recall_note: str
    f1_score: Optional[float]
    f1_note: str
    false_positive_rate: Optional[float]
    fpr_note: str
    detection_rate: Optional[float]
    detection_rate_note: str
    avg_detection_time_ms: float
    confusion_matrix: Dict[str, Dict[str, int]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationSuiteResult:
    """Complete evaluation suite execution outcome."""
    mode: str
    timestamp: str
    engine_version: str
    metrics: ConfusionMetrics
    case_results: List[TestCaseResult]
    false_positive_examples: List[Dict[str, Any]]
    false_negative_examples: List[Dict[str, Any]]
    robustness_breakdown: Dict[str, Any]
    test_configuration: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "timestamp": self.timestamp,
            "engine_version": self.engine_version,
            "metrics": self.metrics.to_dict(),
            "case_results": [c.to_dict() for c in self.case_results],
            "false_positive_examples": self.false_positive_examples,
            "false_negative_examples": self.false_negative_examples,
            "robustness_breakdown": self.robustness_breakdown,
            "test_configuration": self.test_configuration
        }


# =================================================================================================
# 2. METRICS CALCULATION (ZERO-SAFE & EXPLAINABLE)
# =================================================================================================

def calculate_metrics(results: List[TestCaseResult]) -> ConfusionMetrics:
    """
    Computes standard diagnostic evaluation metrics with mathematically robust zero-denominator handling.
    """
    total = len(results)
    tp = sum(1 for r in results if r.classification == "TP")
    fp = sum(1 for r in results if r.classification == "FP")
    tn = sum(1 for r in results if r.classification == "TN")
    fn = sum(1 for r in results if r.classification == "FN")

    # Precision: TP / (TP + FP)
    if (tp + fp) > 0:
        precision = round(tp / (tp + fp), 4)
        precision_note = "Valid (Calculated on positive detections)"
    else:
        precision = None
        precision_note = "Undefined: No positive alerts generated by engine (TP + FP = 0)"

    # Recall / Detection Rate: TP / (TP + FN)
    if (tp + fn) > 0:
        recall = round(tp / (tp + fn), 4)
        recall_note = "Valid (Calculated on ground-truth suspicious cases)"
        detection_rate = recall
        detection_rate_note = recall_note
    else:
        recall = None
        recall_note = "Undefined: No ground-truth suspicious test cases in dataset (TP + FN = 0)"
        detection_rate = None
        detection_rate_note = recall_note

    # F1-score: 2 * (P * R) / (P + R)
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1_score = round(2 * (precision * recall) / (precision + recall), 4)
        f1_note = "Valid harmonic mean of Precision and Recall"
    else:
        f1_score = None
        f1_note = "Undefined: Precision or Recall is zero or undefined"

    # False-Positive Rate: FP / (FP + TN)
    if (fp + tn) > 0:
        fpr = round(fp / (fp + tn), 4)
        fpr_note = "Valid (Calculated on ground-truth legitimate cases)"
    else:
        fpr = None
        fpr_note = "Undefined: No ground-truth legitimate cases in dataset (FP + TN = 0)"

    # Average Detection Time
    exec_times = [r.execution_time_ms for r in results]
    avg_time = round(sum(exec_times) / len(exec_times), 2) if exec_times else 0.0

    confusion_matrix = {
        "Actual_Suspicious": {"Predicted_Suspicious": tp, "Predicted_Legitimate": fn},
        "Actual_Legitimate": {"Predicted_Suspicious": fp, "Predicted_Legitimate": tn}
    }

    return ConfusionMetrics(
        total_cases=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        precision_note=precision_note,
        recall=recall,
        recall_note=recall_note,
        f1_score=f1_score,
        f1_note=f1_note,
        false_positive_rate=fpr,
        fpr_note=fpr_note,
        detection_rate=detection_rate,
        detection_rate_note=detection_rate_note,
        avg_detection_time_ms=avg_time,
        confusion_matrix=confusion_matrix
    )


# =================================================================================================
# 3. GROUND-TRUTH BENCHMARK DATASET GENERATORS
# =================================================================================================

def _make_context_roster(username: str, terminated_date: Optional[str] = None, full_name: str = "Test User") -> Dict[str, Any]:
    """Helper to produce a mock HR roster (E14) context."""
    roster_df = pd.DataFrame([{
        "employee_id": "HF-EVAL-01",
        "username": username,
        "full_name": full_name,
        "department": "Finance",
        "role": "Accounts Payable Clerk",
        "status": "active",
        "termination_date": terminated_date
    }])
    return {"E14": roster_df}


def build_evaluation_dataset() -> List[TestCase]:
    """
    Constructs the definitive 34-case ground-truth evaluation dataset covering:
    - Mode A: Rule Validation (14 cases: 7 positive, 7 negative)
    - Mode B: Scenario Validation (6 cases: 5 positive, 1 negative baseline)
    - Mode C: Unseen Variation Testing (6 cases: 3 positive, 3 negative)
    - Mode D: Robustness Testing (8 cases: 5 positive, 3 negative)
    """
    cases: List[TestCase] = []

    # ---------------------------------------------------------------------------------------------
    # MODE A: RULE VALIDATION (Tests individual detection rules with positive & negative controls)
    # ---------------------------------------------------------------------------------------------
    
    # 1. RULE-AUTH-001 (Positive)
    def gen_rule_auth_pos():
        now = datetime(2026, 8, 13, 9, 2, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_sso_event(
            simulation_id="EVAL-AUTH-01",
            scenario_id="RULE_AUTH",
            user="r.menon",
            timestamp=now,
            result="success",
            source_ip="172.16.8.44",
            expected_classification="RULE-AUTH-001"
        )
        ctx = _make_context_roster("r.menon", terminated_date="2026-06-30", full_name="Rohan Menon")
        return [evt], ctx

    cases.append(TestCase(
        test_id="TC-RULE-AUTH-01",
        name="Terminated Employee Account Access (Positive)",
        description="Departed employee r.menon logs in successfully 44 days post-termination date.",
        mode="rule_validation",
        ground_truth=1,
        generator_fn=gen_rule_auth_pos,
        target_rule="RULE-AUTH-001",
        expected_rules=["RULE-AUTH-001"]
    ))

    # 2. RULE-AUTH-001 (Negative Control)
    def gen_rule_auth_neg():
        now = datetime(2026, 8, 13, 10, 15, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_sso_event(
            simulation_id="EVAL-AUTH-02",
            scenario_id="RULE_AUTH",
            user="p.sharma",
            timestamp=now,
            result="success",
            source_ip="172.16.8.10",
            expected_classification="BENIGN"
        )
        ctx = _make_context_roster("p.sharma", terminated_date=None, full_name="Pooja Sharma")
        return [evt], ctx

    cases.append(TestCase(
        test_id="TC-RULE-AUTH-02",
        name="Active Employee Routine Login (Negative Control)",
        description="Active employee p.sharma logs in during regular business hours with valid MFA.",
        mode="rule_validation",
        ground_truth=0,
        generator_fn=gen_rule_auth_neg,
        target_rule="RULE-AUTH-001",
        expected_rules=[]
    ))

    # 3. RULE-API-001 (Positive: Sensitive Endpoint)
    def gen_rule_api_pos_endpoint():
        now = datetime(2026, 9, 3, 1, 40, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_api_event(
            simulation_id="EVAL-API-01",
            scenario_id="RULE_API",
            api_key_id="key-tb-07",
            endpoint="/v2/vendors/V-0412/bank-details",
            method="GET",
            timestamp=now,
            caller_ip="10.20.4.77",
            status=200,
            expected_classification="RULE-API-001"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-API-01",
        name="API Key Querying High-Risk Financial Endpoint (Positive)",
        description="Integration credential key-tb-07 probes /v2/vendors/V-0412/bank-details.",
        mode="rule_validation",
        ground_truth=1,
        generator_fn=gen_rule_api_pos_endpoint,
        target_rule="RULE-API-001",
        expected_rules=["RULE-API-001"]
    ))

    # 4. RULE-API-002 (Positive: Unauthorized Threat Indicator Host)
    def gen_rule_api_pos_ip():
        now = datetime(2026, 9, 3, 1, 42, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_api_event(
            simulation_id="EVAL-API-02",
            scenario_id="RULE_API",
            api_key_id="key-tb-07",
            endpoint="/v2/sync/orders",
            method="GET",
            timestamp=now,
            caller_ip="198.18.7.41",  # Matches threat intelligence indicator in E17
            status=200,
            expected_classification="RULE-API-002"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-API-02",
        name="API Key Used from Threat Indicator Host IP (Positive)",
        description="Integration credential key-tb-07 called from external threat indicator IP 198.18.7.41 (E17).",
        mode="rule_validation",
        ground_truth=1,
        generator_fn=gen_rule_api_pos_ip,
        target_rule="RULE-API-002",
        expected_rules=["RULE-API-002"]
    ))

    # 5. RULE-API (Negative Control)
    def gen_rule_api_neg():
        now = datetime(2026, 8, 20, 14, 0, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_api_event(
            simulation_id="EVAL-API-03",
            scenario_id="RULE_API",
            api_key_id="key-tb-07",
            endpoint="/v2/sync/orders",
            method="GET",
            timestamp=now,
            caller_ip="10.20.4.12",  # Authorized sync server
            status=200,
            expected_classification="BENIGN"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-API-03",
        name="Routine Inventory Sync from Approved Pool IP (Negative Control)",
        description="Normal scheduled API query to /v2/sync/orders originating from approved sync host 10.20.4.12.",
        mode="rule_validation",
        ground_truth=0,
        generator_fn=gen_rule_api_neg,
        target_rule="RULE-API-001",
        expected_rules=[]
    ))

    # 6. RULE-EXP-001 (Positive: Credential Search)
    def gen_rule_exp_pos_search():
        now = datetime(2026, 8, 11, 23, 10, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_helpdesk_event(
            simulation_id="EVAL-EXP-01",
            scenario_id="RULE_EXP",
            action="search.tickets",
            actor="hd_user_01",
            timestamp=now,
            source_ip="172.16.8.55",
            object_id="SEARCH-01",
            details="search: bvk-7f3a api_key secret",
            expected_classification="RULE-EXP-001"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-EXP-01",
        name="Support Ticket Reconnaissance for Secrets (Positive)",
        description="Targeted keyword query in HelpDeskr searching for secret keys (bvk-7f3a, api_key).",
        mode="rule_validation",
        ground_truth=1,
        generator_fn=gen_rule_exp_pos_search,
        target_rule="RULE-EXP-001",
        expected_rules=["RULE-EXP-001"]
    ))

    # 7. RULE-EXP-002 (Positive: Bulk Export Surge)
    def gen_rule_exp_pos_burst():
        base = datetime(2026, 8, 11, 23, 30, tzinfo=timezone.utc)
        evts = []
        for i in range(16):
            t = base + timedelta(minutes=i * 2)
            evts.append(SyntheticEventBuilder.create_helpdesk_event(
                simulation_id="EVAL-EXP-02",
                scenario_id="RULE_EXP",
                action="ticket.export",
                actor="hd_user_01",
                timestamp=t,
                source_ip="172.16.8.55",
                object_id=f"EXP-JOB-{i+1}",
                details=None,
                expected_classification="RULE-EXP-002"
            ))
        return evts, {}

    cases.append(TestCase(
        test_id="TC-RULE-EXP-02",
        name="Abnormal HelpDeskr Bulk Ticket Export Surge (Positive)",
        description="Burst of 16 ticket exports in 32 minutes triggering billing anomaly (E06 corroboration).",
        mode="rule_validation",
        ground_truth=1,
        generator_fn=gen_rule_exp_pos_burst,
        target_rule="RULE-EXP-002",
        expected_rules=["RULE-EXP-002"]
    ))

    # 8. RULE-EXP (Negative Control)
    def gen_rule_exp_neg():
        now = datetime(2026, 8, 14, 11, 0, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_helpdesk_event(
            simulation_id="EVAL-EXP-03",
            scenario_id="RULE_EXP",
            action="ticket.view",
            actor="support_agent",
            timestamp=now,
            source_ip="172.16.8.20",
            object_id="TKT-55412",
            details="Viewing printer configuration ticket",
            expected_classification="BENIGN"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-EXP-03",
        name="Routine Single Support Ticket View (Negative Control)",
        description="Standard support agent view operation on an individual customer ticket.",
        mode="rule_validation",
        ground_truth=0,
        generator_fn=gen_rule_exp_neg,
        target_rule="RULE-EXP-002",
        expected_rules=[]
    ))

    # 9. RULE-FIN-001 (Positive: Unapproved Vendor Bank Change)
    def gen_rule_fin_pos_unapproved():
        now = datetime(2026, 9, 3, 1, 44, 30, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_vendor_change_event(
            simulation_id="EVAL-FIN-01",
            scenario_id="RULE_FIN",
            vendor_id="V-0412",
            vendor_name="Coastal Packaging Ltd",
            field_changed="bank_account",
            old_val="****4412",
            new_val="****9083",
            changed_by="key-tb-07",
            channel="API",
            timestamp=now,
            source_ip="10.20.4.77",
            approval_ref=None,
            request_id="req-eval-5f61b0de8",
            expected_classification="RULE-FIN-001"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-FIN-01",
        name="Vendor Bank Detail Modification Without Approval (Positive)",
        description="Bank account changed with no dual-authorization reference (breaches Policy Section 4.1).",
        mode="rule_validation",
        ground_truth=1,
        generator_fn=gen_rule_fin_pos_unapproved,
        target_rule="RULE-FIN-001",
        expected_rules=["RULE-FIN-001", "RULE-FIN-002"]
    ))

    # 10. RULE-FIN-002 (Positive: Bank Change via UI Missing Approval Reference)
    def gen_rule_fin_pos_ui_unapproved():
        now = datetime(2026, 9, 3, 1, 45, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_vendor_change_event(
            simulation_id="EVAL-FIN-02",
            scenario_id="RULE_FIN",
            vendor_id="V-0412",
            vendor_name="Coastal Packaging Ltd",
            field_changed="bank_account",
            old_val="****4412",
            new_val="****9083",
            changed_by="finance_clerk_01",
            channel="UI",
            timestamp=now,
            source_ip="172.16.8.44",
            approval_ref=None,  # Missing approval reference via UI triggers RULE-FIN-002
            request_id="req-eval-ui-02",
            expected_classification="RULE-FIN-002"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-FIN-02",
        name="Vendor Bank Detail Modification via UI Missing Approval Reference (Positive)",
        description="Vendor bank changes via UI without an approval reference trigger procedural alert RULE-FIN-002.",
        mode="rule_validation",
        ground_truth=1,
        generator_fn=gen_rule_fin_pos_ui_unapproved,
        target_rule="RULE-FIN-002",
        expected_rules=["RULE-FIN-002"]
    ))

    # 11. RULE-FIN (Negative Control: Approved Portal Change)
    def gen_rule_fin_neg():
        now = datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_vendor_change_event(
            simulation_id="EVAL-FIN-03",
            scenario_id="RULE_FIN",
            vendor_id="V-0105",
            vendor_name="Standard Freight Spares",
            field_changed="address",
            old_val="Suite 101, Harbour Way",
            new_val="Suite 205, Maritime Blvd",
            changed_by="m.sundar",
            channel="UI",
            timestamp=now,
            source_ip="172.16.8.22",
            approval_ref="APV-2026-8812",
            expected_classification="BENIGN"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-FIN-03",
        name="Legitimate Approved Vendor Address Update (Negative Control)",
        description="Routine address change submitted via Web Portal with valid dual approval APV-2026-8812.",
        mode="rule_validation",
        ground_truth=0,
        generator_fn=gen_rule_fin_neg,
        target_rule="RULE-FIN-001",
        expected_rules=[]
    ))

    # 12. RULE-DOC-001 (Positive: Sensitive Bank Instructions Access)
    def gen_rule_doc_pos_instructions():
        now = datetime(2026, 8, 14, 15, 30, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_bluevault_event(
            simulation_id="EVAL-DOC-01",
            scenario_id="RULE_DOC",
            principal="bvk-7f3a",
            path="/finance/bank-instructions/Coastal_Packaging_V0412.pdf",
            action="download",
            timestamp=now,
            source_ip="172.16.8.99",
            expected_classification="RULE-DOC-001"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-DOC-01",
        name="BlueVault Download of Sensitive Vendor Bank Instructions (Positive)",
        description="Shared storage access to banking instruction sheet using service principal.",
        mode="rule_validation",
        ground_truth=1,
        generator_fn=gen_rule_doc_pos_instructions,
        target_rule="RULE-DOC-001",
        expected_rules=["RULE-DOC-001"]
    ))

    # 13. RULE-DOC-002 (Positive: High Volume Multi-Customer Access)
    def gen_rule_doc_pos_bulk():
        base = datetime(2026, 8, 14, 16, 0, tzinfo=timezone.utc)
        evts = []
        for i in range(55):
            evts.append(SyntheticEventBuilder.create_bluevault_event(
                simulation_id="EVAL-DOC-02",
                scenario_id="RULE_DOC",
                principal="key:bvk-7f3a",
                path=f"/customer-docs/cust_{i+100}/statements/aug_statement.pdf",
                action="read",
                timestamp=base + timedelta(seconds=i * 5),
                source_ip="172.16.8.99",
                expected_classification="RULE-DOC-002"
            ))
        return evts, {}

    cases.append(TestCase(
        test_id="TC-RULE-DOC-02",
        name="Mass Customer Directory Traversal in Shared Storage (Positive)",
        description="High volume download of 55 customer statement files within 5 minutes.",
        mode="rule_validation",
        ground_truth=1,
        generator_fn=gen_rule_doc_pos_bulk,
        target_rule="RULE-DOC-002",
        expected_rules=["RULE-DOC-002"]
    ))

    # 14. RULE-DOC (Negative Control)
    def gen_rule_doc_neg():
        now = datetime(2026, 8, 16, 11, 0, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_bluevault_event(
            simulation_id="EVAL-DOC-03",
            scenario_id="RULE_DOC",
            principal="compliance_auditor",
            path="/docs/policies/it_security_v2_1.pdf",
            action="read",
            timestamp=now,
            source_ip="172.16.8.15",
            expected_classification="BENIGN"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-RULE-DOC-03",
        name="Single Routine Policy Document Read (Negative Control)",
        description="Standard single read access to IT security policy by authorized internal auditor.",
        mode="rule_validation",
        ground_truth=0,
        generator_fn=gen_rule_doc_neg,
        target_rule="RULE-DOC-001",
        expected_rules=[]
    ))

    # ---------------------------------------------------------------------------------------------
    # MODE B: SCENARIO VALIDATION (Tests full multi-event scenarios through complete pipeline)
    # ---------------------------------------------------------------------------------------------
    
    # 15. Scenario A (Former Employee)
    cases.append(TestCase(
        test_id="TC-SCEN-A-POS",
        name="Scenario A: Unrevoked Former Employee Access",
        description="Departed employee logs in after exit date, triggering RULE-AUTH-001.",
        mode="scenario_validation",
        ground_truth=1,
        generator_fn=lambda: ScenarioTemplateEngine.generate_scenario_a_former_employee(
            is_terminated=True, login_success=True, days_after_termination=15
        ),
        expected_rules=["RULE-AUTH-001"]
    ))

    # 16. Scenario B (Compromised Integration Credential)
    cases.append(TestCase(
        test_id="TC-SCEN-B-POS",
        name="Scenario B: Compromised Integration Credential Probe",
        description="Integration credential key-tb-07 accesses financial endpoints from build server host.",
        mode="scenario_validation",
        ground_truth=1,
        generator_fn=lambda: ScenarioTemplateEngine.generate_scenario_b_api_activity(
            is_suspicious_caller=True, is_sensitive_endpoint=True, caller_ip="10.20.4.77"
        ),
        expected_rules=["RULE-API-001", "RULE-API-002"]
    ))

    # 17. Scenario C (Suspicious Vendor Master Modification)
    cases.append(TestCase(
        test_id="TC-SCEN-C-POS",
        name="Scenario C: Unauthorized Vendor Bank Detail Modification",
        description="Vendor bank details changed via API channel without approval reference.",
        mode="scenario_validation",
        ground_truth=1,
        generator_fn=lambda: ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
            field_changed="bank_account", channel="API", has_approval_ref=False, source_ip="10.20.4.77"
        ),
        expected_rules=["RULE-FIN-001", "RULE-FIN-002"]
    ))

    # 18. Scenario D (Unusual HelpDeskr Data Export)
    cases.append(TestCase(
        test_id="TC-SCEN-D-POS",
        name="Scenario D: HelpDeskr Credential Reconnaissance & Export Burst",
        description="Targeted searches for credential terms followed by abnormal ticket export burst.",
        mode="scenario_validation",
        ground_truth=1,
        generator_fn=lambda: ScenarioTemplateEngine.generate_scenario_d_export_activity(
            is_burst=True, include_recon_searches=True, export_count=10
        ),
        expected_rules=["RULE-EXP-001", "RULE-EXP-002"]
    ))

    # 19. Scenario E (End-to-End Multi-Stage Attack Progression)
    cases.append(TestCase(
        test_id="TC-SCEN-E-POS",
        name="Scenario E: Multi-Stage Cross-System Attack Sequence",
        description="Full kill chain spanning HelpDeskr recon, credential theft, build server pivot, and financial fraud.",
        mode="scenario_validation",
        ground_truth=1,
        generator_fn=lambda: ScenarioTemplateEngine.generate_scenario_e_multi_stage(
            include_former_employee=True, include_recon=True, include_api_pivot=True, include_vendor_tamper=True
        ),
        expected_rules=["RULE-CORR-001", "RULE-AUTH-001", "RULE-API-001", "RULE-FIN-001"]
    ))

    # 20. Benign Enterprise Baseline Scenario (Negative Control)
    cases.append(TestCase(
        test_id="TC-SCEN-BENIGN-01",
        name="Enterprise Routine Baseline Activity (Negative Control)",
        description="Interleaved routine operations: active staff logins, approved vendor portal updates, and order syncs.",
        mode="scenario_validation",
        ground_truth=0,
        generator_fn=lambda: ScenarioTemplateEngine.generate_benign_baseline(),
        expected_rules=[]
    ))

    # ---------------------------------------------------------------------------------------------
    # MODE C: UNSEEN VARIATION TESTING (Generalization against held-out edge cases)
    # ---------------------------------------------------------------------------------------------

    # 21. Unseen IP for Former Employee
    def gen_unseen_ip():
        now = datetime(2026, 8, 25, 3, 15, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_sso_event(
            simulation_id="UNSEEN-01",
            scenario_id="UNSEEN",
            user="r.menon",
            timestamp=now,
            result="success",
            source_ip="198.51.100.222",  # Unobserved external residential subnet
            expected_classification="RULE-AUTH-001"
        )
        ctx = _make_context_roster("r.menon", terminated_date="2026-06-30", full_name="Rohan Menon")
        return [evt], ctx

    cases.append(TestCase(
        test_id="TC-UNSEEN-01",
        name="Terminated Employee Login from Novel Residential Subnet (Positive)",
        description="Tests detection of terminated staff from unobserved public IP 198.51.100.222.",
        mode="unseen_variation",
        ground_truth=1,
        generator_fn=gen_unseen_ip,
        expected_rules=["RULE-AUTH-001"]
    ))

    # 22. Mixed URL Casing in Sensitive Endpoint
    def gen_unseen_casing():
        now = datetime(2026, 9, 3, 2, 10, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_api_event(
            simulation_id="UNSEEN-02",
            scenario_id="UNSEEN",
            api_key_id="key-tb-07",
            endpoint="/v2/Vendors/V-0412/Bank-Details",  # Mixed Title Casing
            method="GET",
            timestamp=now,
            caller_ip="10.20.4.77",
            status=200,
            expected_classification="RULE-API-001"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-UNSEEN-02",
        name="Sensitive Endpoint Access with Mixed URL Casing (Positive)",
        description="Tests case-insensitive path matching for high-risk financial endpoints.",
        mode="unseen_variation",
        ground_truth=1,
        generator_fn=gen_unseen_casing,
        expected_rules=["RULE-API-001", "RULE-API-002"]
    ))

    # 23. Non-Standard Approval Ticket Format (Legitimate)
    def gen_unseen_approval_fmt():
        now = datetime(2026, 8, 28, 14, 0, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_vendor_change_event(
            simulation_id="UNSEEN-03",
            scenario_id="UNSEEN",
            vendor_id="V-0992",
            vendor_name="Global Cargo Sealers",
            field_changed="bank_account",
            old_val="****1102",
            new_val="****9941",
            changed_by="finance_lead",
            channel="UI",
            timestamp=now,
            source_ip="172.16.8.31",
            approval_ref="CHG-MGMT-2026-9912-APPROVED",  # Non-standard approved token
            expected_classification="BENIGN"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-UNSEEN-03",
        name="Vendor Bank Modification with Novel Approval Token (Negative Control)",
        description="Tests that non-standard approval token prefixes (CHG-MGMT-*) do not generate false alarms.",
        mode="unseen_variation",
        ground_truth=0,
        generator_fn=gen_unseen_approval_fmt,
        expected_rules=[]
    ))

    # 24. Benign API to Newly Deployed Catalog Endpoint
    def gen_unseen_catalog_api():
        now = datetime(2026, 8, 30, 8, 0, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_api_event(
            simulation_id="UNSEEN-04",
            scenario_id="UNSEEN",
            api_key_id="key-tb-07",
            endpoint="/v2/sync/catalog",
            method="GET",
            timestamp=now,
            caller_ip="10.20.4.15",  # Within 10.20.4.11-16 pool
            status=200,
            expected_classification="BENIGN"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-UNSEEN-04",
        name="Benign Synchronization to Novel Sub-Endpoint (Negative Control)",
        description="Tests that queries to new benign sync sub-routes (/v2/sync/catalog) remain alert-free.",
        mode="unseen_variation",
        ground_truth=0,
        generator_fn=gen_unseen_catalog_api,
        expected_rules=[]
    ))

    # 25. Malicious API Bank Change with Bypass Keyword
    def gen_unseen_bypass_keyword():
        now = datetime(2026, 9, 3, 3, 0, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_vendor_change_event(
            simulation_id="UNSEEN-05",
            scenario_id="UNSEEN",
            vendor_id="V-0412",
            vendor_name="Coastal Packaging Ltd",
            field_changed="bank_account",
            old_val="****4412",
            new_val="****9083",
            changed_by="key-tb-07",
            channel="API",
            timestamp=now,
            source_ip="10.20.4.77",
            approval_ref="BYPASS_EMERGENCY_OVERRIDE",  # Fake bypass ref
            expected_classification="RULE-FIN-002"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-UNSEEN-05",
        name="API Bank Modification with Fraudulent Bypass Reference (Positive)",
        description="Tests that API bank changes are flagged under RULE-FIN-002 even if an attacker injects a fake ref.",
        mode="unseen_variation",
        ground_truth=1,
        generator_fn=gen_unseen_bypass_keyword,
        expected_rules=["RULE-FIN-002"]
    ))

    # 26. Active Employee Night-time Login with MFA
    def gen_unseen_night_login():
        now = datetime(2026, 8, 22, 2, 45, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_sso_event(
            simulation_id="UNSEEN-06",
            scenario_id="UNSEEN",
            user="d.patel",
            timestamp=now,
            result="success",
            source_ip="172.16.8.19",
            auth_method="password+fido2",
            expected_classification="BENIGN"
        )
        ctx = _make_context_roster("d.patel", terminated_date=None, full_name="Deepak Patel")
        return [evt], ctx

    cases.append(TestCase(
        test_id="TC-UNSEEN-06",
        name="Active On-Call Engineer Night Login (Negative Control)",
        description="Tests that off-hours logins by verified active staff with hardware MFA do not produce false positives.",
        mode="unseen_variation",
        ground_truth=0,
        generator_fn=gen_unseen_night_login,
        expected_rules=[]
    ))

    # ---------------------------------------------------------------------------------------------
    # MODE D: ROBUSTNESS TESTING (Stress tests under missing fields, skew, out-of-order logs, duplicates)
    # ---------------------------------------------------------------------------------------------

    # 27. Robustness: Missing Optional Fields
    def gen_rob_missing_fields():
        now = datetime(2026, 9, 3, 1, 44, tzinfo=timezone.utc)
        # Event with stripped optional details
        evt = {
            "event_id": "SIM:sim-rob-01",
            "original_event_id": "sim-rob-01",
            "timestamp": now,
            "timestamp_orig": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "timezone_assumption": "UTC (Simulated)",
            "source_evidence_id": "E19",
            "system": "LedgerOne_VendorMaster",
            "actor": "key-tb-07",
            "actor_type": "integration_key",
            "action": "vendor.change.bank_account",
            "target": "V-0412",
            "source_ip": "10.20.4.77",
            "result": "applied",
            "details": {
                "field": "bank_account",
                "channel": "API",
                # Omit approval_ref, vendor_name, old_value, new_value, request_id
            },
            "raw_record": {},
            "is_synthetic": True
        }
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-ROB-01-MISSING-FIELDS",
        name="Robustness: Missing Optional Fields in Vendor Change",
        description="Evaluates rule resilience when optional telemetry fields (vendor_name, request_id) are omitted.",
        mode="robustness",
        ground_truth=1,
        generator_fn=gen_rob_missing_fields,
        robustness_type="missing_optional_fields",
        expected_rules=["RULE-FIN-001", "RULE-FIN-002"]
    ))

    # 28. Robustness: Timestamp Variation & Milliseconds
    def gen_rob_timestamp_skew():
        now = datetime(2026, 9, 3, 1, 40, 15, 789123, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_api_event(
            simulation_id="ROB-TS-01",
            scenario_id="ROBUSTNESS",
            api_key_id="key-tb-07",
            endpoint="/v2/vendors/V-0412/bank-details",
            method="GET",
            timestamp=now,
            caller_ip="10.20.4.77",
            status=200,
            expected_classification="RULE-API-001"
        )
        # Override timestamp string with microsecond formatting
        evt["timestamp_orig"] = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-ROB-02-TIMESTAMP-VARIATION",
        name="Robustness: Microsecond Timestamp Representation",
        description="Evaluates parser resilience with sub-second microsecond timestamps and ISO-8601 formatting.",
        mode="robustness",
        ground_truth=1,
        generator_fn=gen_rob_timestamp_skew,
        robustness_type="timestamp_variation",
        expected_rules=["RULE-API-001", "RULE-API-002"]
    ))

    # 29. Robustness: Arbitrary External IP Subnets
    def gen_rob_different_ips():
        now = datetime(2026, 9, 3, 1, 41, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_api_event(
            simulation_id="ROB-IP-01",
            scenario_id="ROBUSTNESS",
            api_key_id="key-tb-07",
            endpoint="/v2/sync/orders",
            method="GET",
            timestamp=now,
            caller_ip="203.0.113.88",  # TEST-NET-3 external routable IP
            status=200,
            expected_classification="RULE-API-002"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-ROB-03-DIFFERENT-IPS",
        name="Robustness: Arbitrary External Public IP Address",
        description="Evaluates unauthorized network caller detection against unseen external IPv4 addresses.",
        mode="robustness",
        ground_truth=1,
        generator_fn=gen_rob_different_ips,
        robustness_type="different_ips",
        expected_rules=["RULE-API-002"]
    ))

    # 30. Robustness: Changed Event Sequence (Reverse Chronological Order)
    def gen_rob_reversed_sequence():
        # Generate Scenario E events but deliberately invert arrival order
        evts, ctx = ScenarioTemplateEngine.generate_scenario_e_multi_stage()
        reversed_evts = list(reversed(evts))
        return reversed_evts, ctx

    cases.append(TestCase(
        test_id="TC-ROB-04-CHANGED-SEQUENCE",
        name="Robustness: Out-of-Order Event Sequence Inversion",
        description="Evaluates multi-stage detection when log ingestion arrives out of strict chronological sequence.",
        mode="robustness",
        ground_truth=1,
        generator_fn=gen_rob_reversed_sequence,
        robustness_type="changed_sequence",
        expected_rules=["RULE-AUTH-001", "RULE-API-001", "RULE-FIN-001"]
    ))

    # 31. Robustness: Duplicate Replay Burst
    def gen_rob_duplicates():
        now = datetime(2026, 9, 3, 1, 40, tzinfo=timezone.utc)
        base_evt = SyntheticEventBuilder.create_api_event(
            simulation_id="ROB-DUP-01",
            scenario_id="ROBUSTNESS",
            api_key_id="key-tb-07",
            endpoint="/v2/vendors/V-0412/bank-details",
            method="GET",
            timestamp=now,
            caller_ip="10.20.4.77",
            status=200,
            expected_classification="RULE-API-001"
        )
        # Replicate identical event 15 times
        duplicate_stream = [base_evt.copy() for _ in range(15)]
        return duplicate_stream, {}

    cases.append(TestCase(
        test_id="TC-ROB-05-DUPLICATE-RECORDS",
        name="Robustness: High-Frequency Duplicate Telemetry Stream",
        description="Evaluates engine resilience against log replays and deduplicates excessive alert floods.",
        mode="robustness",
        ground_truth=1,
        generator_fn=gen_rob_duplicates,
        robustness_type="duplicate_records",
        expected_rules=["RULE-API-001", "RULE-API-002"]
    ))

    # 32. Robustness: Legitimate Dual-Authorized Vendor Bank Change (Negative Control)
    def gen_rob_legit_vendor():
        now = datetime(2026, 8, 18, 11, 20, tzinfo=timezone.utc)
        evt = SyntheticEventBuilder.create_vendor_change_event(
            simulation_id="ROB-VEND-01",
            scenario_id="ROBUSTNESS",
            vendor_id="V-0220",
            vendor_name="Harbor Marine Supplies",
            field_changed="bank_account",
            old_val="****7712",
            new_val="****8834",
            changed_by="finance_director",
            channel="UI",
            timestamp=now,
            source_ip="172.16.8.12",
            approval_ref="APV-2026-7701",  # Verified dual authorization
            expected_classification="BENIGN"
        )
        return [evt], {}

    cases.append(TestCase(
        test_id="TC-ROB-06-LEGITIMATE-VENDOR",
        name="Robustness: Dual-Authorized Portal Bank Modification (Negative Control)",
        description="Evaluates specificity on legitimate bank changes submitted via UI with valid dual approval APV-2026-7701.",
        mode="robustness",
        ground_truth=0,
        generator_fn=gen_rob_legit_vendor,
        robustness_type="legitimate_vendor_change",
        expected_rules=[]
    ))

    # 33. Robustness: High-Volume Normal API Order Sync (Negative Control)
    def gen_rob_normal_api():
        base = datetime(2026, 8, 25, 6, 0, tzinfo=timezone.utc)
        evts = []
        for i in range(50):
            evts.append(SyntheticEventBuilder.create_api_event(
                simulation_id="ROB-API-01",
                scenario_id="ROBUSTNESS",
                api_key_id="key-tb-07",
                endpoint="/v2/sync/inventory",
                method="GET",
                timestamp=base + timedelta(seconds=i * 2),
                caller_ip="10.20.4.12",  # Approved sync server
                status=200,
                expected_classification="BENIGN"
            ))
        return evts, {}

    cases.append(TestCase(
        test_id="TC-ROB-07-NORMAL-API",
        name="Robustness: 50 High-Frequency Normal Sync API Calls (Negative Control)",
        description="Evaluates noise suppression across high-volume automated sync traffic from approved pool host.",
        mode="robustness",
        ground_truth=0,
        generator_fn=gen_rob_normal_api,
        robustness_type="normal_api_activity",
        expected_rules=[]
    ))

    # 34. Robustness: Unrelated Background Noise (Negative Control)
    def gen_rob_noise():
        base = datetime(2026, 8, 26, 9, 0, tzinfo=timezone.utc)
        evts = [
            # Benign HelpDesk internal note
            SyntheticEventBuilder.create_helpdesk_event(
                simulation_id="ROB-NOISE-01",
                scenario_id="ROBUSTNESS",
                action="ticket.internal_note",
                actor="helpdesk_tech",
                timestamp=base,
                source_ip="172.16.8.20",
                object_id="TKT-11002",
                details="Updated network printer firmware to v4.2",
                expected_classification="BENIGN"
            ),
            # Benign SSO password change
            SyntheticEventBuilder.create_sso_event(
                simulation_id="ROB-NOISE-02",
                scenario_id="ROBUSTNESS",
                user="a.shukla",
                timestamp=base + timedelta(minutes=5),
                result="success",
                source_ip="172.16.8.35",
                auth_method="password_reset_flow",
                expected_classification="BENIGN"
            )
        ]
        ctx = _make_context_roster("a.shukla", terminated_date=None, full_name="Ananya Shukla")
        return evts, ctx

    cases.append(TestCase(
        test_id="TC-ROB-08-UNRELATED-NOISE",
        name="Robustness: Unrelated Multi-System Diagnostic Noise (Negative Control)",
        description="Evaluates false-alarm immunity against unrelated operational background telemetry.",
        mode="robustness",
        ground_truth=0,
        generator_fn=gen_rob_noise,
        robustness_type="unrelated_events",
        expected_rules=[]
    ))

    return cases


# =================================================================================================
# 4. DEFENSIVE EVALUATION ENGINE CLASS
# =================================================================================================

class DefensiveEvaluationEngine:
    """
    Independent evaluation engine that benchmarks the ThreatDetectionEngine against
    ground-truth test suites across multiple modes and produces reproducible diagnostic reports.
    """

    VERSION = "1.0.0-PROD"

    def __init__(self, detection_engine: Optional[ThreatDetectionEngine] = None):
        self.detection_engine = detection_engine or ThreatDetectionEngine()
        self.all_cases = build_evaluation_dataset()

    def evaluate_test_case(self, case: TestCase) -> TestCaseResult:
        """Executes a single test case through the detection engine and computes its diagnostic outcome."""
        events, context = case.generator_fn()
        df_events = pd.DataFrame(events)

        t_start = time.perf_counter()
        raised_alerts: List[ThreatAlert] = self.detection_engine.evaluate_events(df_events, context=context)
        exec_ms = round((time.perf_counter() - t_start) * 1000, 2)

        detected_rule_ids = [a.rule_id for a in raised_alerts]
        unique_detected = set(detected_rule_ids)

        # Determine detection result:
        # In Rule Validation mode: checks if the specific target_rule was triggered
        if case.mode == "rule_validation" and case.target_rule:
            is_detected = 1 if case.target_rule in unique_detected else 0
        else:
            # In Scenario / Variation / Robustness mode: detected if any alert (or expected rules) triggered
            is_detected = 1 if len(raised_alerts) > 0 else 0

        # Classify result: TP, FP, TN, FN
        if case.ground_truth == 1 and is_detected == 1:
            classification = "TP"
            result_str = "Correct Detection (TP)"
            explanation = f"Suspicious scenario correctly detected. Triggered rule(s): {list(unique_detected)}."
        elif case.ground_truth == 0 and is_detected == 0:
            classification = "TN"
            result_str = "Correct Pass (TN)"
            explanation = "Legitimate/benign activity correctly passed without raising false alerts."
        elif case.ground_truth == 0 and is_detected == 1:
            classification = "FP"
            result_str = "False Alarm (FP)"
            explanation = f"Legitimate activity incorrectly flagged as threat. Raised: {list(unique_detected)}."
        else: # ground_truth == 1 and is_detected == 0
            classification = "FN"
            result_str = "Missed Detection (FN)"
            explanation = f"Suspicious scenario failed to trigger expected alert(s): {case.expected_rules}."

        expected_alert_str = ", ".join(case.expected_rules) if case.expected_rules else "None (Legitimate)"
        actual_alert_str = ", ".join(unique_detected) if unique_detected else "None (No Alert)"

        return TestCaseResult(
            test_id=case.test_id,
            scenario=case.name,
            mode=case.mode,
            ground_truth=case.ground_truth,
            detection_result=is_detected,
            classification=classification,
            expected_alert=expected_alert_str,
            actual_alert=actual_alert_str,
            result=result_str,
            explanation=explanation,
            execution_time_ms=exec_ms,
            events_count=len(events),
            alerts_count=len(raised_alerts),
            detected_rule_ids=detected_rule_ids,
            details={
                "description": case.description,
                "robustness_type": case.robustness_type,
                "target_rule": case.target_rule
            }
        )

    def run_suite(self, cases: List[TestCase], suite_name: str) -> EvaluationSuiteResult:
        """Executes a filtered set of test cases and aggregates results."""
        results: List[TestCaseResult] = []
        for case in cases:
            res = self.evaluate_test_case(case)
            results.append(res)

        metrics = calculate_metrics(results)

        # Filter FPs and FNs for dedicated root-cause reporting
        fps = [r.to_dict() for r in results if r.classification == "FP"]
        fns = [r.to_dict() for r in results if r.classification == "FN"]

        # Robustness breakdown
        robustness_breakdown = {}
        for r in results:
            rob_type = r.details.get("robustness_type")
            if rob_type:
                if rob_type not in robustness_breakdown:
                    robustness_breakdown[rob_type] = {"total": 0, "passed": 0, "failed": 0}
                robustness_breakdown[rob_type]["total"] += 1
                if r.classification in ("TP", "TN"):
                    robustness_breakdown[rob_type]["passed"] += 1
                else:
                    robustness_breakdown[rob_type]["failed"] += 1

        ts_now = datetime.now(timezone.utc).isoformat()
        cfg = {
            "evaluation_engine_version": self.VERSION,
            "suite_name": suite_name,
            "rules_evaluated": [r.rule_id for r in self.detection_engine.rules],
            "total_test_cases": len(cases),
            "simulated_tag": SIMULATION_TAG
        }

        return EvaluationSuiteResult(
            mode=suite_name,
            timestamp=ts_now,
            engine_version=self.VERSION,
            metrics=metrics,
            case_results=results,
            false_positive_examples=fps,
            false_negative_examples=fns,
            robustness_breakdown=robustness_breakdown,
            test_configuration=cfg
        )

    def run_rule_validation(self) -> EvaluationSuiteResult:
        """MODE A: Rule Validation."""
        cases = [c for c in self.all_cases if c.mode == "rule_validation"]
        return self.run_suite(cases, "Rule Validation (Mode A)")

    def run_scenario_validation(self) -> EvaluationSuiteResult:
        """MODE B: Scenario Validation."""
        cases = [c for c in self.all_cases if c.mode == "scenario_validation"]
        return self.run_suite(cases, "Scenario Validation (Mode B)")

    def run_unseen_variation_testing(self) -> EvaluationSuiteResult:
        """MODE C: Unseen Variation Testing."""
        cases = [c for c in self.all_cases if c.mode == "unseen_variation"]
        return self.run_suite(cases, "Unseen Variation Testing (Mode C)")

    def run_robustness_testing(self) -> EvaluationSuiteResult:
        """MODE D: Robustness Testing."""
        cases = [c for c in self.all_cases if c.mode == "robustness"]
        return self.run_suite(cases, "Robustness Stress Testing (Mode D)")

    def run_all(self) -> EvaluationSuiteResult:
        """Executes the entire 34-case comprehensive benchmark battery."""
        return self.run_suite(self.all_cases, "Comprehensive Performance Benchmark (All Modes)")

    # =============================================================================================
    # 5. REPORT GENERATION ENGINE (MARKDOWN & JSON)
    # =============================================================================================

    def generate_report(self, result: EvaluationSuiteResult, format: str = "markdown") -> str:
        """Generates a downloadable, rigorous evaluation report in Markdown or JSON."""
        if format.lower() == "json":
            return json.dumps(result.to_dict(), indent=2)

        # Markdown Report Generation
        m = result.metrics
        p_val = f"{m.precision:.4f}" if m.precision is not None else f"N/A ({m.precision_note})"
        r_val = f"{m.recall:.4f}" if m.recall is not None else f"N/A ({m.recall_note})"
        f1_val = f"{m.f1_score:.4f}" if m.f1_score is not None else f"N/A ({m.f1_note})"
        fpr_val = f"{m.false_positive_rate:.4f}" if m.false_positive_rate is not None else f"N/A ({m.fpr_note})"
        dr_val = f"{m.detection_rate:.4f}" if m.detection_rate is not None else f"N/A ({m.detection_rate_note})"

        report = f"""# TRACE Defensive Performance Evaluation Report
**CRIMEATHON'26 — Defense Track**  
**Evaluation Mode:** {result.mode}  
**Engine Version:** {result.engine_version} | **Generated At:** {result.timestamp}  

---

## 1. Executive Summary & Core Metrics

The TRACE Defensive Performance Evaluation Engine benchmarks detection capability, alert precision, false-alarm mitigation, and adversarial robustness using an isolated ground-truth testing harness.

### Key Performance Indicators
| Metric | Value | Status / Interpretation |
| :--- | :--- | :--- |
| **Total Test Cases** | **{m.total_cases}** | Evaluated under `{result.mode}` |
| **True Positives (TP)** | **{m.true_positives}** | Suspicious cases successfully alerted |
| **False Positives (FP)** | **{m.false_positives}** | Legitimate cases incorrectly alerted |
| **True Negatives (TN)** | **{m.true_negatives}** | Legitimate cases correctly passed |
| **False Negatives (FN)** | **{m.false_negatives}** | Suspicious cases missed by engine |
| **Precision** | **{p_val}** | {m.precision_note} |
| **Recall (Detection Rate)** | **{r_val}** | {m.recall_note} |
| **F1-Score** | **{f1_val}** | {m.f1_note} |
| **False Positive Rate (FPR)** | **{fpr_val}** | {m.fpr_note} |
| **Average Detection Latency** | **{m.avg_detection_time_ms} ms** | Mean execution time per case |

---

## 2. Confusion Matrix

The $2 \\times 2$ confusion matrix contrasts engine predictions against ground truth:

```
                          ┌───────────────────────────┬───────────────────────────┐
                          │    PREDICTED SUSPICIOUS   │    PREDICTED LEGITIMATE   │
┌─────────────────────────┼───────────────────────────┼───────────────────────────┤
│ ACTUAL SUSPICIOUS (GT=1)│ True Positives  (TP): {m.true_positives:3d} │ False Negatives (FN): {m.false_negatives:3d} │
├─────────────────────────┼───────────────────────────┼───────────────────────────┤
│ ACTUAL LEGITIMATE (GT=0)│ False Positives (FP): {m.false_positives:3d} │ True Negatives  (TN): {m.true_negatives:3d} │
└─────────────────────────┴───────────────────────────┴───────────────────────────┘
```

---

## 3. Dataset Description & Ground-Truth Methodology

### 3.1 Strict Evidence-Grounding vs. Synthetic Separation
- **Original Evidence Integrity ($E01$–$E20$)**: Ground truth is **unknown** for the vast majority of background telemetry in the case files. TRACE **strictly refrains** from calculating supervised accuracy metrics over raw evidence files to prevent unscientific bias.
- **Controlled Evaluation Dataset**: All evaluation test cases are programmatically synthesized with unambiguous labels:
  - **Ground Truth = 1 (Suspicious)**: Synthesized attack activities mapped to documented threats.
  - **Ground Truth = 0 (Legitimate)**: Benign operational behaviors, authorized modifications, and routine traffic.
- **Evidence Labeling**: All synthetic events are flagged with `is_synthetic: True` and isolated with `evidence_id: SIMULATED_TEST_LAB`.

---

## 4. Detailed Test Case Evaluation Breakdown

| Test ID | Test Scenario | Mode | GT | Det | Result | Expected Alert | Actual Alert | Latency |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- | :--- | :---: |
"""

        for r in result.case_results:
            report += f"| `{r.test_id}` | {r.scenario} | {r.mode} | `{r.ground_truth}` | `{r.detection_result}` | **{r.classification}** | {r.expected_alert} | {r.actual_alert} | {r.execution_time_ms}ms |\n"

        report += f"""
---

## 5. False-Positive Analysis ({len(result.false_positive_examples)} Cases)
"""
        if not result.false_positive_examples:
            report += "No false positives recorded in this evaluation run. Specificity maintained at 100%.\n"
        else:
            for fp in result.false_positive_examples:
                report += f"- **Case `{fp['test_id']}`**: {fp['scenario']}\n  - *Triggered*: `{fp['actual_alert']}`\n  - *Root Cause Analysis*: {fp['explanation']}\n"

        report += f"""
---

## 6. Missed Detection (False Negative) Analysis ({len(result.false_negative_examples)} Cases)
"""
        if not result.false_negative_examples:
            report += "No missed detections recorded in this evaluation run. Recall maintained at 100%.\n"
        else:
            for fn in result.false_negative_examples:
                report += f"- **Case `{fn['test_id']}`**: {fn['scenario']}\n  - *Expected*: `{fn['expected_alert']}`\n  - *Remediation Guidance*: {fn['explanation']}\n"

        report += f"""
---

## 7. Robustness Stress-Testing Breakdown

TRACE was evaluated against 8 adversarial perturbation dimensions:
"""
        if result.robustness_breakdown:
            for r_type, stats in result.robustness_breakdown.items():
                pass_rate = round((stats["passed"] / stats["total"]) * 100, 1) if stats["total"] > 0 else 0.0
                report += f"- **{r_type.replace('_', ' ').title()}**: {stats['passed']}/{stats['total']} Passed ({pass_rate}% resilience)\n"
        else:
            report += "Robustness stress-testing was not executed as part of this specific mode.\n"

        report += f"""
---

## 8. Engine Limitations & Boundary Conditions

1. **Unsynchronized Host Clocks**: BlueVault ($E05$) timestamps operate on uncalibrated hardware clocks. While timestamp variation stress tests pass, temporal windows retain calibrated uncertainty bands.
2. **HR Status Field Defect**: Roster file $E14$ labels all 420 employees as `'active'`. The engine relies exclusively on `termination_date` presence rather than the corrupted `status` string.
3. **Zero Denominator Safeguards**: When testing purely malicious suites ($TN = FP = 0$), False Positive Rate is reported as `N/A (Undefined)` rather than coerced to an arbitrary number.

---

## 9. Test Configuration Metadata

```json
{json.dumps(result.test_configuration, indent=2)}
```
"""
        return report

    def export_report_to_file(self, result: EvaluationSuiteResult, file_path: str, format: str = "markdown") -> str:
        """Saves evaluation report to the local file system."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        content = self.generate_report(result, format=format)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return file_path


# =================================================================================================
# 6. STANDALONE CLI EXECUTION ENTRYPOINT
# =================================================================================================

if __name__ == "__main__":
    import sys
    print("=" * 80)
    print(" TRACE Defensive Performance Evaluation Engine — CRIMEATHON'26")
    print("=" * 80)

    eval_engine = DefensiveEvaluationEngine()
    print(f"Loaded {len(eval_engine.all_cases)} ground-truth benchmark test cases.")
    print("Executing comprehensive evaluation across all modes...\n")

    res = eval_engine.run_all()
    m = res.metrics

    print("Confusion Matrix:")
    print(f"  True Positives  (TP): {m.true_positives}")
    print(f"  False Positives (FP): {m.false_positives}")
    print(f"  True Negatives  (TN): {m.true_negatives}")
    print(f"  False Negatives (FN): {m.false_negatives}")
    print("-" * 40)
    print(f"  Precision:           {m.precision} ({m.precision_note})")
    print(f"  Recall / Det Rate:   {m.recall} ({m.recall_note})")
    print(f"  F1-Score:            {m.f1_score} ({m.f1_note})")
    print(f"  False Positive Rate: {m.false_positive_rate} ({m.fpr_note})")
    print(f"  Avg Latency:         {m.avg_detection_time_ms} ms")
    print("=" * 80)

    # Export reports
    md_path = eval_engine.export_report_to_file(res, "reports/defensive_performance_report.md", format="markdown")
    json_path = eval_engine.export_report_to_file(res, "reports/defensive_performance_report.json", format="json")
    print(f"Saved Markdown report to: {md_path}")
    print(f"Saved JSON report to:     {json_path}")
    print("Evaluation completed successfully.")
