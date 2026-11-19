# TRACE — Technical Architecture & Engineering Report
**Competition:** CRIMEATHON'26 — Defense Track  
**Case File:** CR-26-047 (Harbor & Finch Freight Pvt. Ltd.)  
**Engine:** TRACE (Threat Recognition, Analysis and Correlation Engine)  
**Version:** 1.0.0-PROD  
**Author:** Lead Python Developer & Cybersecurity Detection Engineer  

---

## 1. Executive Summary & Core Objective

TRACE is an evidence-grounded cybersecurity defense engine engineered to ingest, normalize, detect, correlate, and explain suspicious activities across disparate enterprise systems. Built for the CRIMEATHON'26 Defense Track, TRACE evaluates heterogeneous operational telemetry (spanning financial APIs, customer support logs, identity providers, object storage, and private network tunnels) against strict data integrity requirements without inventing missing values, fabricating evidence, or asserting guilt without forensic proof.

---

## 2. System Architecture & Modular Design

```
crimeathon/
├── app.py                         # Complete 6-page interactive Streamlit SOC application
├── requirements.txt               # Locked dependencies (streamlit, pandas, plotly, networkx, pytest)
├── README.md                      # Production deployment and verification documentation
├── data/
│   └── original/                  # Pristine source evidence archive (E01-E20, strictly read-only)
├── trace_engine/
│   ├── __init__.py
│   ├── alert_schema.py            # Standardized ThreatAlert dataclass with backward-compatible aliases
│   ├── correlation_models.py      # CorrelatedEvent, RelationshipType enum, InvestigationCase schema
│   ├── correlation_scoring.py     # Transparent CaseRiskScorer multi-factor attribution model
│   ├── correlation.py             # CrossSystemCorrelationEngine (Cases 01–04)
│   ├── detection.py               # ThreatDetectionEngine orchestrator & multi-stage synthesizer
│   ├── evaluation.py              # DefensiveEvaluationEngine (Modes A–D, zero-safe metric math)
│   ├── graph_builder.py           # NetworkX topological graph builder & Plotly 2D renderer
│   ├── ingestion.py               # Robust evidence loaders (CSV, JSON, Excel, PDF via pypdf)
│   ├── normalisation.py           # Fast vectorized dictionary normalizer (109,428 events in ~5.7s)
│   ├── risk_scoring.py            # Transparent composite risk score calculator (0.0 to 100.0)
│   ├── rules.py                   # Modular BaseRule detection rules (Auth, API, Doc, Exp, Fin)
│   ├── scenario_templates.py      # Scenarios A–E generators & held-out variation test suites
│   ├── simulation.py              # In-memory synthetic telemetry runner & confusion matrix engine
│   └── synthetic_data.py          # Synthetic telemetry generator (safe, labeled SIMULATED_TEST_LAB)
├── reports/                       # Formal audit reports, timelines, and proof pack artifacts
└── tests/
    ├── __init__.py
    ├── test_foundation.py         # 5 tests: Ingestion, schema mapping, and baseline rules
    ├── test_detection_engine.py   # 8 tests: Rule edge cases, negatives, deduplication, timestamps
    ├── test_correlation_engine.py # 8 tests: Direct ID matching, temporal windows, NetworkX graph
    ├── test_simulation_lab.py     # 7 tests: Scenarios A–E, synthetic isolation, held-out variations
    └── test_evaluation_engine.py  # 10 tests: Metric math, zero-safe division, modes, reproducibility
```

---

## 3. Data Pipeline & Schema Normalisation

```
┌─────────────────────────────────┐
│ Pristine Source Evidence        │ E01-E20 (CSV, JSON, Excel, PDF)
└────────────────┬────────────────┘
                 │ (trace_engine/ingestion.py)
┌────────────────▼────────────────┐
│ Source-Specific Parsers         │ Pandas, openpyxl/XML, pypdf, json
└────────────────┬────────────────┘
                 │ (trace_engine/normalisation.py)
┌────────────────▼────────────────┐
│ Common Event Schema             │ 109,428 normalized records (UTC timestamp, actor, action,
│ Vectorized Normalization        │ source_ip, target, raw_record, evidence_id, drift notes)
└────────────────┬────────────────┘
                 │ (trace_engine/detection.py)
┌────────────────▼────────────────┐
│ Modular Detection Rules         │ 5 Core Rule Classes (RULE-AUTH, RULE-API, RULE-EXP,
│ Threat Alerts Generated         │ RULE-FIN, RULE-DOC) + RULE-CORR Multi-Stage Alert
└────────────────┬────────────────┘
                 │ (trace_engine/correlation.py & graph_builder.py)
┌────────────────▼────────────────┐
│ Cross-System Correlation        │ 4 Dedicated Cases + Typed Relationships +
│ NetworkX Knowledge Graph        │ Transparent Risk Attribution + Interactive Timeline
└────────────────┬────────────────┘
                 │ (Streamlit SOC Interface / app.py)
┌────────────────▼────────────────┐
│ 6-Page Interactive Dashboard    │ Security Overview, Evidence Centre, Threat Detection,
│ Plotly Visualizations           │ Workspace, Simulation Lab, Performance Lab
└─────────────────────────────────┘
```

### Timezone Strategy & Handling
1. **UTC Timestamps (`E01`, `E18`, `E03`, `E15`, `E19`)**: Standardized directly as ISO 8601 UTC with offset `+00:00`.
2. **Indian Standard Time (IST, UTC+05:30) (`E02`, `E13`, `E06`, `E12`, `E16`)**: Converted to UTC by parsing local datetime strings (`DD/MM/YYYY HH:MM:SS` or `YYYY-MM-DD HH:MM`) and subtracting $5\text{ hours } 30\text{ minutes}$. Original local strings are preserved verbatim in `timestamp_orig`.
3. **Unix Epoch Seconds (`E05`)**: Converted to UTC via `datetime.fromtimestamp(epoch, tz=timezone.utc)`. *Known Hardware Defect*: BlueVault clock was never NTP-synchronized; events carry an explicit `uncertainty_notes` disclaimer.

---

## 4. Detection Logic & Modular Rules

| Rule ID | Rule Name | Threat Category | Evidence Cited | Detection Logic | Primary Case Finding |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **RULE-AUTH-001** | Post-Termination Account Access | Identity & Access | E14, E03, E09, E11 | Cross-references SSO sign-ins with HR departure date. Flags successful logins occurring $>1$ day post-exit. | Rohan Menon (`r.menon`), departed 30 June 2026, logged in on 13 Aug 2026 (`sso-bb8ab61e08`). |
| **RULE-API-001** | High-Risk Endpoint & Build Server Invocation | API Security | E01, E18, E04, E15 | Flags integration keys calling sensitive financial endpoints (`/v2/vendors/*/bank-details`, `/v2/payments/scheduled`) or originating from internal build host `10.20.4.77` (`tb-build-02`). | `key-tb-07` issued GET on Coastal Packaging bank details from `10.20.4.77` on 3 Sep 2026. |
| **RULE-API-002** | Network Boundary & IOC Gateway Match | Network Security | E01, E18, E04, E17 | Identifies API requests originating from unauthorized network CIDRs outside approved sync pool (`10.20.4.11-16`) or matching external threat indicators. | Detects calls from non-pool CIDRs and matches vendor-reported indicators (`198.18.7.41`). |
| **RULE-EXP-001** | Support Ticket Credential Reconnaissance | Reconnaissance | E02, E13 | Flags targeted keyword searches in customer support tickets searching for secret strings (`password`, `api_key`, `secret`, `bearer`, `bvk-`). | Multiple searches for `bvk-` and secret keys in HelpDeskr on 11 Aug 2026. |
| **RULE-EXP-002** | Abnormal Bulk Ticket Export Burst | Data Exfiltration | E02, E06 | Identifies abnormal bursts of bulk ticket export jobs ($>10$ exports in 60 mins), corroborating HelpDeskr overage billing alerts. | 30 bulk export jobs executed on 11–12 Aug 2026, triggering E06 overage invoice. |
| **RULE-FIN-001** | Unauthorised Vendor Bank Modification (API) | Financial Integrity | E19, E18, E10 | Detects vendor bank-account changes executed via automated API channels or lacking an approval reference. | Bank account for Coastal Packaging Ltd (`V-0412`) changed to `****9083` via API without approval ref (`req-5f61b0de8`). |
| **RULE-FIN-002** | Vendor Master Procedural Dual-Control Breach | Governance | E19, E10 | Flags portal UI vendor bank modifications submitted without a valid approval ticket reference, violating Policy Section 4.1. | Enforces strict dual-authorization compliance across all vendor master changes. |
| **RULE-DOC-001** | Sensitive Financial Statement Access | Storage Security | E05, E13 | Identifies access to vendor bank instruction sheets (`/finance/bank-instructions/`) in shared object storage. | Shared storage access to Coastal Packaging bank instructions file. |
| **RULE-DOC-002** | Horizontal Storage Key Privilege Abuse | Storage Security | E05, E13 | Detects horizontal customer traversal where a single client access key (`bvk-7f3a`) is used across $>10$ distinct client folders. | Key `bvk-7f3a` (leaked in ticket `TKT-48213`) traversed 143 customer directories. |
| **RULE-CORR-001** | Cross-System Attack Progression Chain | Correlation | E02, E05, E15, E18, E19 | Synthesizes multi-stage attack sequence across distinct systems: Reconnaissance -> Secret Exfiltration -> Host Pivot -> Payment Tampering. | Correlates the full TallyBridge supply-chain breach leading to fraudulent diversion of $8\text{ Sep}$ payment run. |

---

## 5. Correlation Methodology & Graph Architecture

### Four Typed Relationships
1. **Direct Identifier Matching**: Exact correlation across system boundaries using factual common identifiers (`r.menon`, `key-tb-07`, `10.20.4.77`, `req-5f61b0de8`, `V-0412`, `bvk-7f3a`).
2. **Temporal Correlation**: Bounded time windows connecting sequential actions across systems. Incorporates clock drift caveats where hardware timekeeping was unsynchronized.
3. **Contextual Association**: Structural relationships documented in integration registers ($E04$), contracts ($E08$), and staff rosters ($E14$).
4. **Unverified Association**: Third-party intelligence and self-reported notices ($E12$, $E16$, $E17$) preserved with explicit unverified tags to prevent confirmation bias.

### Transparent Case Risk Scoring Model

$$\text{Composite Score} = \min(100.0, \, S_{\text{systems}} + S_{\text{direct\_matches}} + S_{\text{policy\_breach}} + S_{\text{kill\_chain}} - P_{\text{uncertainty}})$$

* **Systems Diversity ($+15.0 \text{ pts per system}$)**: Rewards multi-system corroboration.
* **Direct Identifier Matches ($+10.0 \text{ pts per match}$)**: Factual cross-log joins.
* **Policy & Control Breaches ($+20.0 \text{ pts}$)**: Dual-authorization bypasses.
* **Kill-Chain Progression ($+15.0 \text{ pts}$)**: End-to-end multi-stage synthesis.
* **Uncertainty Deductions ($-5.0 \text{ to } -15.0 \text{ pts}$)**: Penalties for unsynchronized clocks or unverified indicators.

---

## 6. Simulation & Evaluation Performance Results

The Defensive Performance Evaluation Engine benchmarks TRACE against a 34-case ground-truth dataset across 4 evaluation modes:

```
================================================================================
 TRACE Defensive Performance Evaluation Engine — Empirical Results
================================================================================
Total Benchmark Test Cases:     34
True Positives (TP):            22
False Positives (FP):           0
True Negatives (TN):            12
False Negatives (FN):           0
--------------------------------------------------------------------------------
Precision:                      100.0% (1.000)
Recall (Detection Rate):        100.0% (1.000)
F1-Score:                       1.000
False Positive Rate (FPR):      0.0% (0.000)
Average Execution Latency:      9.5 ms per case
Robustness Stress Resilience:   100.0% (8 of 8 perturbation dimensions passed)
================================================================================
```

---

## 7. Operational Limitations & Forensic Boundaries

1. **Unsynchronized Hardware Clocks**: BlueVault ($E05$) timestamps operate on uncalibrated hardware clocks. Chronological sequence relative to LedgerOne is approximate; correlation relies on principal IDs and paths rather than sub-minute temporal correlation.
2. **HR Status Column Defect**: Roster file $E14$ records all 420 personnel as `'active'`. The engine ignores the corrupted `status` column and relies strictly on `termination_date`.
3. **Vendor Self-Reported Notices**: Information in $E12$ and $E16$ represents external third-party statements. TRACE treats them as corroborative context rather than independent forensic proof.
4. **Presumption of Innocence**: No individual is accused of criminal guilt; the engine strictly reports observed events, policy violations, and deprovisioning failures.
