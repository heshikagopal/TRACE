# TRACE Defensive Performance Evaluation Report
**CRIMEATHON'26 — Defense Track**  
**Evaluation Mode:** Comprehensive Performance Benchmark (All Modes)  
**Engine Version:** 1.0.0-PROD | **Generated At:** 2026-11-19T13:17:05.299731+00:00  

---

## 1. Executive Summary & Core Metrics

The TRACE Defensive Performance Evaluation Engine benchmarks detection capability, alert precision, false-alarm mitigation, and adversarial robustness using an isolated ground-truth testing harness.

### Key Performance Indicators
| Metric | Value | Status / Interpretation |
| :--- | :--- | :--- |
| **Total Test Cases** | **34** | Evaluated under `Comprehensive Performance Benchmark (All Modes)` |
| **True Positives (TP)** | **22** | Suspicious cases successfully alerted |
| **False Positives (FP)** | **0** | Legitimate cases incorrectly alerted |
| **True Negatives (TN)** | **12** | Legitimate cases correctly passed |
| **False Negatives (FN)** | **0** | Suspicious cases missed by engine |
| **Precision** | **1.0000** | Valid (Calculated on positive detections) |
| **Recall (Detection Rate)** | **1.0000** | Valid (Calculated on ground-truth suspicious cases) |
| **F1-Score** | **1.0000** | Valid harmonic mean of Precision and Recall |
| **False Positive Rate (FPR)** | **0.0000** | Valid (Calculated on ground-truth legitimate cases) |
| **Average Detection Latency** | **9.5 ms** | Mean execution time per case |

---

## 2. Confusion Matrix

The $2 \times 2$ confusion matrix contrasts engine predictions against ground truth:

```
                          ┌───────────────────────────┬───────────────────────────┐
                          │    PREDICTED SUSPICIOUS   │    PREDICTED LEGITIMATE   │
┌─────────────────────────┼───────────────────────────┼───────────────────────────┤
│ ACTUAL SUSPICIOUS (GT=1)│ True Positives  (TP):  22 │ False Negatives (FN):   0 │
├─────────────────────────┼───────────────────────────┼───────────────────────────┤
│ ACTUAL LEGITIMATE (GT=0)│ False Positives (FP):   0 │ True Negatives  (TN):  12 │
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
| `TC-RULE-AUTH-01` | Terminated Employee Account Access (Positive) | rule_validation | `1` | `1` | **TP** | RULE-AUTH-001 | RULE-AUTH-001 | 11.06ms |
| `TC-RULE-AUTH-02` | Active Employee Routine Login (Negative Control) | rule_validation | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 13.27ms |
| `TC-RULE-API-01` | API Key Querying High-Risk Financial Endpoint (Positive) | rule_validation | `1` | `1` | **TP** | RULE-API-001 | RULE-API-001 | 10.8ms |
| `TC-RULE-API-02` | API Key Used from Threat Indicator Host IP (Positive) | rule_validation | `1` | `1` | **TP** | RULE-API-002 | RULE-API-002 | 5.06ms |
| `TC-RULE-API-03` | Routine Inventory Sync from Approved Pool IP (Negative Control) | rule_validation | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 10.35ms |
| `TC-RULE-EXP-01` | Support Ticket Reconnaissance for Secrets (Positive) | rule_validation | `1` | `1` | **TP** | RULE-EXP-001 | RULE-EXP-001 | 10.32ms |
| `TC-RULE-EXP-02` | Abnormal HelpDeskr Bulk Ticket Export Surge (Positive) | rule_validation | `1` | `1` | **TP** | RULE-EXP-002 | RULE-EXP-002 | 7.82ms |
| `TC-RULE-EXP-03` | Routine Single Support Ticket View (Negative Control) | rule_validation | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 11.32ms |
| `TC-RULE-FIN-01` | Vendor Bank Detail Modification Without Approval (Positive) | rule_validation | `1` | `1` | **TP** | RULE-FIN-001, RULE-FIN-002 | RULE-FIN-001 | 4.54ms |
| `TC-RULE-FIN-02` | Vendor Bank Detail Modification via UI Missing Approval Reference (Positive) | rule_validation | `1` | `1` | **TP** | RULE-FIN-002 | RULE-FIN-002 | 8.77ms |
| `TC-RULE-FIN-03` | Legitimate Approved Vendor Address Update (Negative Control) | rule_validation | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 5.27ms |
| `TC-RULE-DOC-01` | BlueVault Download of Sensitive Vendor Bank Instructions (Positive) | rule_validation | `1` | `1` | **TP** | RULE-DOC-001 | RULE-DOC-001 | 11.89ms |
| `TC-RULE-DOC-02` | Mass Customer Directory Traversal in Shared Storage (Positive) | rule_validation | `1` | `1` | **TP** | RULE-DOC-002 | RULE-DOC-002 | 9.66ms |
| `TC-RULE-DOC-03` | Single Routine Policy Document Read (Negative Control) | rule_validation | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 5.98ms |
| `TC-SCEN-A-POS` | Scenario A: Unrevoked Former Employee Access | scenario_validation | `1` | `1` | **TP** | RULE-AUTH-001 | RULE-AUTH-001 | 9.98ms |
| `TC-SCEN-B-POS` | Scenario B: Compromised Integration Credential Probe | scenario_validation | `1` | `1` | **TP** | RULE-API-001, RULE-API-002 | RULE-API-001 | 5.27ms |
| `TC-SCEN-C-POS` | Scenario C: Unauthorized Vendor Bank Detail Modification | scenario_validation | `1` | `1` | **TP** | RULE-FIN-001, RULE-FIN-002 | RULE-API-001, RULE-FIN-001 | 9.86ms |
| `TC-SCEN-D-POS` | Scenario D: HelpDeskr Credential Reconnaissance & Export Burst | scenario_validation | `1` | `1` | **TP** | RULE-EXP-001, RULE-EXP-002 | RULE-EXP-001, RULE-EXP-002 | 12.12ms |
| `TC-SCEN-E-POS` | Scenario E: Multi-Stage Cross-System Attack Sequence | scenario_validation | `1` | `1` | **TP** | RULE-CORR-001, RULE-AUTH-001, RULE-API-001, RULE-FIN-001 | RULE-EXP-001, RULE-FIN-001, RULE-CORR-001, RULE-AUTH-001, RULE-API-001, RULE-EXP-002 | 16.35ms |
| `TC-SCEN-BENIGN-01` | Enterprise Routine Baseline Activity (Negative Control) | scenario_validation | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 16.62ms |
| `TC-UNSEEN-01` | Terminated Employee Login from Novel Residential Subnet (Positive) | unseen_variation | `1` | `1` | **TP** | RULE-AUTH-001 | RULE-AUTH-001 | 8.89ms |
| `TC-UNSEEN-02` | Sensitive Endpoint Access with Mixed URL Casing (Positive) | unseen_variation | `1` | `1` | **TP** | RULE-API-001, RULE-API-002 | RULE-API-001 | 7.02ms |
| `TC-UNSEEN-03` | Vendor Bank Modification with Novel Approval Token (Negative Control) | unseen_variation | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 12.84ms |
| `TC-UNSEEN-04` | Benign Synchronization to Novel Sub-Endpoint (Negative Control) | unseen_variation | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 4.74ms |
| `TC-UNSEEN-05` | API Bank Modification with Fraudulent Bypass Reference (Positive) | unseen_variation | `1` | `1` | **TP** | RULE-FIN-002 | RULE-FIN-001 | 7.89ms |
| `TC-UNSEEN-06` | Active On-Call Engineer Night Login (Negative Control) | unseen_variation | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 7.07ms |
| `TC-ROB-01-MISSING-FIELDS` | Robustness: Missing Optional Fields in Vendor Change | robustness | `1` | `1` | **TP** | RULE-FIN-001, RULE-FIN-002 | RULE-FIN-001 | 5.78ms |
| `TC-ROB-02-TIMESTAMP-VARIATION` | Robustness: Microsecond Timestamp Representation | robustness | `1` | `1` | **TP** | RULE-API-001, RULE-API-002 | RULE-API-001 | 6.13ms |
| `TC-ROB-03-DIFFERENT-IPS` | Robustness: Arbitrary External Public IP Address | robustness | `1` | `1` | **TP** | RULE-API-002 | RULE-API-002 | 6.68ms |
| `TC-ROB-04-CHANGED-SEQUENCE` | Robustness: Out-of-Order Event Sequence Inversion | robustness | `1` | `1` | **TP** | RULE-AUTH-001, RULE-API-001, RULE-FIN-001 | RULE-EXP-001, RULE-FIN-001, RULE-CORR-001, RULE-AUTH-001, RULE-API-001, RULE-EXP-002 | 17.76ms |
| `TC-ROB-05-DUPLICATE-RECORDS` | Robustness: High-Frequency Duplicate Telemetry Stream | robustness | `1` | `1` | **TP** | RULE-API-001, RULE-API-002 | RULE-API-001 | 8.44ms |
| `TC-ROB-06-LEGITIMATE-VENDOR` | Robustness: Dual-Authorized Portal Bank Modification (Negative Control) | robustness | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 7.07ms |
| `TC-ROB-07-NORMAL-API` | Robustness: 50 High-Frequency Normal Sync API Calls (Negative Control) | robustness | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 10.72ms |
| `TC-ROB-08-UNRELATED-NOISE` | Robustness: Unrelated Multi-System Diagnostic Noise (Negative Control) | robustness | `0` | `0` | **TN** | None (Legitimate) | None (No Alert) | 15.79ms |

---

## 5. False-Positive Analysis (0 Cases)
No false positives recorded in this evaluation run. Specificity maintained at 100%.

---

## 6. Missed Detection (False Negative) Analysis (0 Cases)
No missed detections recorded in this evaluation run. Recall maintained at 100%.

---

## 7. Robustness Stress-Testing Breakdown

TRACE was evaluated against 8 adversarial perturbation dimensions:
- **Missing Optional Fields**: 1/1 Passed (100.0% resilience)
- **Timestamp Variation**: 1/1 Passed (100.0% resilience)
- **Different Ips**: 1/1 Passed (100.0% resilience)
- **Changed Sequence**: 1/1 Passed (100.0% resilience)
- **Duplicate Records**: 1/1 Passed (100.0% resilience)
- **Legitimate Vendor Change**: 1/1 Passed (100.0% resilience)
- **Normal Api Activity**: 1/1 Passed (100.0% resilience)
- **Unrelated Events**: 1/1 Passed (100.0% resilience)

---

## 8. Engine Limitations & Boundary Conditions

1. **Unsynchronized Host Clocks**: BlueVault ($E05$) timestamps operate on uncalibrated hardware clocks. While timestamp variation stress tests pass, temporal windows retain calibrated uncertainty bands.
2. **HR Status Field Defect**: Roster file $E14$ labels all 420 employees as `'active'`. The engine relies exclusively on `termination_date` presence rather than the corrupted `status` string.
3. **Zero Denominator Safeguards**: When testing purely malicious suites ($TN = FP = 0$), False Positive Rate is reported as `N/A (Undefined)` rather than coerced to an arbitrary number.

---

## 9. Test Configuration Metadata

```json
{
  "evaluation_engine_version": "1.0.0-PROD",
  "suite_name": "Comprehensive Performance Benchmark (All Modes)",
  "rules_evaluated": [
    "RULE-AUTH-001",
    "RULE-API-001",
    "RULE-EXP-001",
    "RULE-FIN-001",
    "RULE-DOC-001"
  ],
  "total_test_cases": 34,
  "simulated_tag": "SIMULATED_TEST_LAB"
}
```
