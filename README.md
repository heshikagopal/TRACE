# TRACE — Threat Recognition, Analysis & Correlation Engine

<p align="center">
  <strong>CRIMEATHON'26 | DEFENSE TRACK</strong>
</p>

<p align="center">
  An intelligent cybersecurity investigation and threat detection platform designed to identify, analyze, correlate, and contain sophisticated cyber-enabled financial fraud.
</p>

<p align="center">
  <a href="https://crimeathon1.vercel.app/">
    <img src="https://img.shields.io/badge/LIVE%20DEMO-Visit%20TRACE-22C55E?style=for-the-badge" />
  </a>
  <a href="https://github.com/heshikagopal/TRACE">
    <img src="https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github" />
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Tests-38%2F38%20Passing-22C55E?style=flat-square" />
  <img src="https://img.shields.io/badge/Detection%20Benchmark-8%2F8-22C55E?style=flat-square" />
  <img src="https://img.shields.io/badge/False%20Positives-0-22C55E?style=flat-square" />
  <img src="https://img.shields.io/badge/Track-Defensive%20Cybersecurity-blue?style=flat-square" />
</p>

---

## 1. Overview

**TRACE (Threat Recognition, Analysis and Correlation Engine)** is a dual-interface cybersecurity defense and behavioral forensics platform developed for **CRIMEATHON'26 – Defense Track**.

TRACE investigates complex cyber-enabled financial fraud by analyzing activities across multiple enterprise systems, identifying suspicious behavioral patterns, correlating digital evidence, and supporting incident containment.

Unlike traditional security systems that primarily depend on IP blocklists, TRACE uses **Behavioral Contracts** to distinguish legitimate activities from suspicious behavior.

### Investigation Case

| Detail | Information |
|---|---|
| Case ID | CR-26-047 |
| Organization | Harbor & Finch Freight Pvt. Ltd. |
| Target Vendor | Coastal Packaging Ltd. |
| Vendor ID | V-0412 |
| Financial Exposure | $48,920 |
| Attack Objective | Unauthorized vendor bank-account modification |
| Investigation Status | Resolved and contained in the case simulation |

### The Incident

The investigation focuses on an attempted financial fraud involving the replacement of a legitimate vendor bank account with a fraudulent account before a scheduled vendor disbursement.

The reconstructed attack sequence includes:

1. **Reconnaissance:** Suspicious API probes using a deprecated SDK client.
2. **Credential Exposure:** Discovery of a cloud backup key in customer support records.
3. **Cloud Access:** Unauthorized access to financial storage resources.
4. **Internal Movement:** Suspicious activity involving an internal build server.
5. **Financial Tampering:** An unauthorized API request attempting to modify vendor banking information.

TRACE correlates evidence from multiple enterprise systems to reconstruct the incident and demonstrate defensive containment.

---

## 2. Key Features

### Intelligent Threat Detection
- Behavioral-contract-based security monitoring.
- Detection of suspicious API activity.
- SDK version and network behavior validation.
- Identification of unusual access patterns.
- Transparent risk scoring.

### Digital Forensics & Evidence Correlation
- Multi-format evidence ingestion.
- Timestamp normalization across different time zones.
- Cross-system event correlation.
- Interactive entity relationship graphs.
- Reconstructed incident timelines.

### Interactive Cybersecurity Dashboard
- Live-style security monitoring interface.
- Interactive attack timeline replay.
- Visual breach relationship graph.
- Communication corridor monitoring.
- Security metrics and benchmark visualization.

### Incident Containment
- Payment-run protection simulation.
- Three-stage verification mechanism.
- Banking information validation.
- Interactive rollback demonstration.
- Financial exposure monitoring.

### Simulation & Evaluation
- Five adversary simulation scenarios.
- Eight robustness testing dimensions.
- Benchmark comparison against traditional IP blocklists.
- Automated test suite.
- Exportable forensic reports.

---

## 3. System Architecture

TRACE consists of two complementary interfaces.

### Interface 1: SOC Workstation – Python Backend

**Main file:** `app.py`

Technologies:
- Python 3.10+
- Streamlit
- Pandas
- NumPy
- NetworkX

Responsibilities:
- Evidence ingestion and normalization.
- Forensic investigation.
- Threat detection and risk scoring.
- Entity relationship graph generation.
- Adversary simulation.
- Defensive evaluation.
- Report generation.

### Interface 2: Cyber HUD – Frontend Dashboard

**Main file:** `index.html`

Technologies:
- HTML5
- CSS3
- Vanilla JavaScript
- SVG

Responsibilities:
- Security telemetry visualization.
- Interactive attack timeline.
- Threat relationship visualization.
- Payment protection simulation.
- Incident containment demonstration.
- Security benchmark presentation.

### Architecture Flow

```text
       ENTERPRISE EVIDENCE FILES
              E01 – E20
                  |
                  v
        DATA INGESTION ENGINE
                  |
                  v
       NORMALIZATION & VALIDATION
                  |
                  v
        BEHAVIORAL DETECTION
                  |
                  v
       CROSS-SYSTEM CORRELATION
                  |
          +-------+-------+
          |               |
          v               v
    SOC WORKSTATION    CYBER HUD
      (Python)         (Frontend)
          |               |
          v               v
    FORENSIC REPORTS   VISUAL MONITORING
          |               |
          +-------+-------+
                  |
                  v
         INCIDENT CONTAINMENT
```

---

## 4. Technology Stack

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Frontend | HTML5, CSS3, JavaScript |
| Backend Framework | Streamlit |
| Data Processing | Pandas, NumPy |
| Graph Analysis | NetworkX |
| Visualization | SVG, CSS, JavaScript |
| Data Formats | CSV, JSON, Excel, PDF |
| Testing | Python Unittest |
| Deployment | Vercel |
| Version Control | Git & GitHub |

---

## 5. Evidence Processing

TRACE processes 20 competition evidence files (E01–E20), containing heterogeneous enterprise records.

| Evidence | Source | Investigative Purpose |
|---|---|---|
| E01 | LedgerOne API Logs | Baseline API activity |
| E02 | HelpDeskr Audit Logs | Suspicious support activity |
| E03 | SSO Sign-in Logs | Authentication investigation |
| E04 | Connected Software Register | Integration policy validation |
| E05 | BlueVault Access Logs | Cloud access investigation |
| E06 | Billing Alert & Invoice | Evidence of bulk exports |
| E07 | Onboarding Review | Vendor due diligence |
| E08 | Contract Excerpt | Security obligations |
| E09 | Risk Register | Institutional risk identification |
| E10 | IT Security Policy | Security policy validation |
| E11 | Internal Audit Report | Historical audit findings |
| E12 | Email Notice | Security advisory |
| E13 | Support Chat Export | Credential exposure investigation |
| E14 | Staff Roster | Employee verification |
| E15 | Network Flow Logs | Internal infrastructure mapping |
| E16 | Follow-up Email | Workstation compromise evidence |
| E17 | Indicator List | External threat indicators |
| E18 | API Access Logs | Suspicious API modifications |
| E19 | Vendor Change Log | Banking modification evidence |
| E20 | Public Records | Infrastructure investigation |

---

## 6. Performance & Evaluation Metrics

The following values represent the project's documented competition benchmark and test results.

| Metric | Result |
|---|---:|
| Evidence Files | 20 |
| Processed Records | 109,428 |
| Attack Stages Detected | 8/8 |
| Benchmark Detection Rate | 100% |
| False Positives | 0 |
| Legitimate Employees Preserved | 14 |
| Automated Unit Tests | 38/38 |
| Average Processing Latency | 1.2 ms |
| Defensive Quality Score | 98.6% |

**Important:** These are results from the supplied competition evidence and documented benchmark/simulation environment, not independently validated production deployment results.

---

## 7. Project Structure

```text
TRACE/
│
├── app.py
├── index.html
├── styles.css
├── app.js
├── events.json
├── contracts.json
├── metrics.json
├── requirements.txt
├── vercel.json
│
├── frontend/
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   ├── events.json
│   ├── contracts.json
│   └── metrics.json
│
├── data/
│   └── original/
│       └── E01 – E20
│
├── trace_engine/
│   ├── ingestion.py
│   ├── normalisation.py
│   ├── alert_schema.py
│   ├── risk_scoring.py
│   ├── rules.py
│   ├── detection.py
│   ├── correlation_models.py
│   ├── correlation_scoring.py
│   ├── graph_builder.py
│   ├── correlation.py
│   ├── synthetic_data.py
│   ├── scenario_templates.py
│   ├── simulation.py
│   └── evaluation.py
│
├── reports/
│   ├── competition_technical_report.md
│   ├── reconstructed_incident_timeline.md
│   ├── evidence_mapping_report.md
│   ├── defensive_performance_report.md
│   ├── defensive_performance_report.json
│   ├── testing_and_qa_audit_report.md
│   └── competition_demonstration_script.md
│
├── tests/
│   ├── test_foundation.py
│   ├── test_detection_engine.py
│   ├── test_correlation_engine.py
│   ├── test_simulation_lab.py
│   └── test_evaluation_engine.py
│
└── .github/
    └── workflows/
        └── gh-pages.yml
```

---

## 8. Installation & Setup

### Prerequisites

- Python 3.10, 3.11, or 3.12
- Git
- A web browser

### Step 1: Clone the Repository

```bash
git clone https://github.com/heshikagopal/TRACE.git
cd TRACE
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Run Automated Tests

```bash
python -m unittest discover tests
```

Expected result: 38 tests passing.

### Step 4: Launch the Cyber HUD

```bash
python -m http.server 8000
```

Open:

```text
http://localhost:8000/
```

### Step 5: Launch the SOC Workstation

```bash
streamlit run app.py
```

Open:

```text
http://localhost:8501/
```

---

## 9. Live Deployment

Experience the TRACE Cyber HUD through the deployed application.

<p align="center">
  <a href="https://crimeathon1.vercel.app/">
    <img src="https://img.shields.io/badge/OPEN%20LIVE%20PROJECT-TRACE-22C55E?style=for-the-badge" />
  </a>
</p>

**Live Demo:** https://crimeathon1.vercel.app/

**GitHub Repository:** https://github.com/heshikagopal/TRACE

---

## 10. Team & Contributors

Built collaboratively for **CRIMEATHON'26 – Defense Track**.

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/heshikagopal">
        <img src="https://github.com/heshikagopal.png" width="100px;" alt="Heshika Gopal"/>
        <br />
        <sub><b>Heshika Gopal</b></sub>
      </a>
      <br />
      <sub>Project Lead</sub>
    </td>
    <td align="center">
      <a href="https://github.com/Nikitha2509">
        <img src="https://github.com/Nikitha2509.png" width="100px;" alt="Nikitha"/>
        <br />
        <sub><b>Nikitha</b></sub>
      </a>
      <br />
      <sub>Contributor</sub>
    </td>
    <td align="center">
      <a href="https://github.com/kowshikashish">
        <img src="https://github.com/kowshikashish.png" width="100px;" alt="Kowshik Ashish"/>
        <br />
        <sub><b>Kowshik Ashish</b></sub>
      </a>
      <br />
      <sub>Contributor</sub>
    </td>
  </tr>
</table>

We collaborated on developing TRACE, combining cybersecurity concepts, evidence analysis, threat correlation, and interactive visualization to demonstrate a comprehensive defensive investigation platform.

**Team:** AAZHI

---

## 11. Ethical Considerations

TRACE is designed as a defensive cybersecurity investigation and simulation platform.

- No active network scanning is performed.
- No real credential attacks are conducted.
- Synthetic adversary scenarios are restricted to isolated testing environments.
- Evidence analysis focuses on defensive investigation and incident response.
- The rollback functionality is demonstrated within the project's case simulation.

---

## 12. Future Enhancements

Potential directions for further development include:

- Integration with live Security Information and Event Management (SIEM) platforms.
- Real-time security event ingestion.
- Advanced machine learning-based anomaly detection.
- Automated incident response integrations.
- Enhanced threat intelligence correlation.
- Multi-organization monitoring capabilities.

---

## 13. Acknowledgements

We thank the CRIMEATHON'26 organizers for providing the opportunity to explore cybersecurity challenges and develop a defensive investigation solution.

---

<p align="center">
  <strong>TRACE — Turning Digital Evidence into Actionable Cyber Defense.</strong>
</p>

<p align="center">
  Built with dedication by Team AAZHI.
</p>
