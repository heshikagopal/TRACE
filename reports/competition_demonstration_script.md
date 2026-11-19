# TRACE — Competition Demonstration Script (3–5 Minute Presentation)
**Competition:** CRIMEATHON'26 — Defense Track  
**Case File:** CR-26-047 (Harbor & Finch Freight Pvt. Ltd.)  
**Engine:** TRACE (Threat Recognition, Analysis and Correlation Engine)  
**Presenter Role:** Team Lead & Cybersecurity Detection Engineer  

---

## Presentation Overview & Timing Breakdown

| Stage | Duration | Primary Focus & Visual Aid | Key Message to Judges |
| :---: | :---: | :--- | :--- |
| **1** | 0:00 – 0:45 | **The Case Problem & Architecture** (`Page 1: Security Overview`) | Dual incident reality: vendor supply-chain compromise vs. deprovisioning delay. |
| **2** | 0:45 – 1:30 | **Pristine Evidence Ingestion** (`Page 2: Evidence Centre`) | Ingested 109,428 heterogeneous records across 20 files without data loss or modification. |
| **3** | 1:30 – 2:30 | **Threat Detection Engine** (`Page 3: Threat Detection`) | 5 evidence-grounded rules; objective risk scoring; detection of bank change before 8 Sep payment. |
| **4** | 2:30 – 3:30 | **Cross-System Correlation** (`Page 4: Investigation Workspace`) | NetworkX 2D graph, chronological timeline, facts vs. hypotheses separation. |
| **5** | 3:30 – 4:15 | **Controlled Simulation Lab** (`Page 5: Simulation Lab`) | Safe in-memory synthetic telemetry; zero external network risk; variation testing. |
| **6** | 4:15 – 5:00 | **Performance Evaluation** (`Page 6: Performance Lab`) | 34-case ground truth; zero-safe metrics; 100% precision & recall; 38 passing unit tests. |

---

## Verbatim Speaker Script

### 1. The Case Problem & Architecture (0:00 – 0:45)
> "Judges, welcome. We are the engineering team behind **TRACE** — the Threat Recognition, Analysis and Correlation Engine.
>
> In Case **CR-26-047**, Harbor & Finch Freight was faced with potential enterprise intrusion. Rather than assuming a single isolated attacker, TRACE’s evidence-driven analysis revealed **two distinct security failures**:
> 1. **A critical third-party vendor supply-chain compromise** of TallyBridge Connect, where an attacker pivoted through a build server to execute an unauthorized bank detail modification scheduled for payment diversion on September 8th.
> 2. **A systemic identity deprovisioning failure**, where a terminated Accounts Payable clerk logged in 44 days post-exit.
>
> Our architecture is built on six modular pillars: from pristine ingestion and unified event normalisation, to graph correlation, local simulation, and reproducible evaluation."

---

### 2. Evidence Ingestion & Pristine Integrity (0:45 – 1:30)
*(Navigate to Page 2: Evidence Centre)*
> "Let’s look at the **Evidence Centre**. Here we have all twenty pristine evidence files — spanning CSVs, JSON integration contracts, Excel risk registers, and PDF audits.
>
> In cybersecurity defense, data integrity is paramount:
> - **We never modify source evidence**: Original files in `data/original/` remain byte-for-byte read-only.
> - **We never discard original timestamps**: Our vectorized engine ingested **109,428 heterogeneous events in under 6 seconds**, standardizing UTC offsets while preserving the original local timestamps.
> - **We account for real-world defects**: For example, in BlueVault storage ($E05$), the hardware clock was unsynchronized; TRACE flags this with an explicit drift caveat rather than fabricating false temporal certainty. And in HR roster $E14$, where a defect marked all staff active, TRACE relies strictly on factual termination dates."

---

### 3. Threat Detection & Objective Risk Scoring (1:30 – 2:30)
*(Navigate to Page 3: Threat Detection)*
> "Moving to **Threat Detection**, TRACE does not rely on static mock metrics or black-box guesses. We engineered five modular detection rule families:
> - Post-Termination Access (`RULE-AUTH-001`)
> - Sensitive Financial API Probing (`RULE-API-001`)
> - Network Boundary Infractions (`RULE-API-002`)
> - Support Ticket Secret Searches and Bulk Exports (`RULE-EXP-001/002`)
> - Unauthorized Vendor Master Bank Modification (`RULE-FIN-001/002`)
>
> Notice this critical alert: on September 3rd at 01:44 UTC, integration key `key-tb-07` originating from internal build host `10.20.4.77` issued a PATCH modifying Coastal Packaging's bank account to `****9083` without an approval reference. TRACE computes an objective composite risk score of **96.0 / 100**, and immediately advises a tactical payment hold before the September 8th automated disbursements."

---

### 4. Cross-System Correlation & NetworkX Graph (2:30 – 3:30)
*(Navigate to Page 4: Investigation Workspace)*
> "An isolated alert is noise; correlation creates actionable intelligence. In the **Investigation Workspace**, TRACE links events across four distinct relationship types: Direct Match, Temporal, Contextual, and Unverified.
>
> Look at our interactive **NetworkX topological graph**:
> - It links the leaked key in support chat ($E13$) to BlueVault storage downloads ($E05$),
> - connects private-link flow logs ($E15$) identifying `10.20.4.77` as `tb-build-02`,
> - and ties it directly to the financial modification in LedgerOne ($E18/E19$).
>
> Notice on the right our **Facts vs. Hypotheses** panel: TRACE strictly separates verified forensic observations from investigative theories, ensuring no individual is unfairly accused without proof."

---

### 5. Controlled Cybersecurity Simulation Lab (3:30 – 4:15)
*(Navigate to Page 5: Simulation Lab)*
> "How do we verify our defense against adversarial evasion? We built the **Controlled Simulation Lab**.
>
> This lab is completely self-contained. It generates synthetic telemetry locally in-memory and **never attacks or connects to real networks**.
> Every record is tagged with `is_synthetic: True` and isolated under `SIMULATED_TEST_LAB`.
>
> Watch as we configure Scenario C with an unapproved API bank change: clicking 'Generate & Run' passes the synthetic stream through the **exact same production detection engine**, confirming that `RULE-FIN-001` triggers accurately while approved portal updates pass cleanly."

---

### 6. Defensive Evaluation & Conclusion (4:15 – 5:00)
*(Navigate to Page 6: Performance Lab)*
> "Finally, in the **Performance Lab**, we present our rigorous defensive evaluation.
>
> Across 34 ground-truth benchmark test cases, TRACE achieves:
> - **100% Precision ($FP = 0$)**
> - **100% Recall ($FN = 0$)**
> - **1.000 F1-Score**
> - **100% Resilience across all eight robustness stress dimensions**, including missing optional fields, microsecond timestamp jitter, novel external IPs, and out-of-order log delivery.
> - Our automated test suite of **38 unit tests runs in 18 seconds with a 100% pass rate**.
>
> Both the full Markdown report and JSON data can be exported with a single click.
>
> TRACE is fully demonstrable, scientifically sound, and live on GitHub. Thank you, and we welcome your questions!"
