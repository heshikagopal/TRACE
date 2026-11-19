# TRACE — Frontend Architecture CHANGELOG

## CRIMEATHON'26 Defense Track — Harbor & Finch Freight Security

### Summary of Enhancements

1. **Evidence Drill-Down Side Panel (Goal 1)**
   - Implemented an animated slide-over inspection drawer for any breach or set-aside event.
   - Structured forensic reporting:
     - **What Happened**: Detailed factual narrative from case evidence files.
     - **Contract Rule Broken**: Side-by-side comparison of **Expected Contract Specification** vs. **Observed Anomaly**.
     - **Supporting Evidence Citations**: Interactive tags referencing files $E01, E02, E05, E10, E13, E15, E19$.
     - **Ordinary Explanations Evaluated**: Clear statement of the innocent hypothesis considered and the forensic rationale for rejecting or accepting it.
     - **Falsification Criteria**: Explicitly documents what evidence would change our mind.

2. **Behavioral Contract Inspector (Goal 2)**
   - Lane headers (`key-tb-07`, `tb-sync-svc`, `bvk-7f3a`, `sso-corporate`) are interactive cards.
   - Clicking opens the full contract card detailing:
     - Allowed Network Pool (CIDR / host limits).
     - Client Version & Formal Retirement Dates.
     - Scheduled Operational Time Windows.
     - Allowed Endpoints & Field Access Scopes.
     - Dual-Control Approval Rules.
   - Displays real observed telemetry directly overlaid on each clause with compliance status.

3. **Cross-System Breach Graph View (Goal 3)**
   - Added a top-bar mode switcher morphing between **Shipping Lanes Timeline** and **Cross-System Breach Graph**.
   - Graphs nodes across the 4 systems and renders typed causal edges:
     - Shared Attacker IP Subnet (`198.18.7.0/24`).
     - Ticket Credential Leak ($TKT-48213 \rightarrow bvk-7f3a$).
     - Build Host Pivot (`10.20.4.77 tb-build-02`).
     - Vendor Payment Diversion ($V-0412 \rightarrow ****9083$).
   - Direct node interaction launches the Evidence Drill-Down drawer.

4. **Payment-Run Padlock Gate Simulator (Goal 4)**
   - Created an interactive ERP payment gate simulator standing before the 8 September disbursement run.
   - Added a 3-step date scrubber (3 Sep intake $\rightarrow$ 5 Sep review $\rightarrow$ 8 Sep payment cutoff).
   - Interactive 3-point Out-of-Band Callback Verification checklist.
   - Interactive rollback action reverting Coastal Packaging ($V-0412$) to verified account `****1142`, protecting \$284,500.

5. **Attack Mutator Concept Demo (Goal 5)**
   - Built a live parameter mutator allowing judges to vary source IP, client version, API key, time window, and approval tokens.
   - Real-time detector impact matrix showing which detectors fire and which are missed.
   - Transparently labeled as a synthetic concept demo with honest reporting of missed detections.

6. **Honest Metrics Scoreboard (Goal 6)**
   - Scoreboard loaded asynchronously from `metrics.json`.
   - Side-by-side comparison between TRACE (100% detection, 0 false alarms on legitimate staff, 5 set aside correctly) vs. Traditional IOC Blocklist (14 false alarms on shared broadband, 5 misses).
   - Displayed tuning disclaimer acknowledging that detectors were calibrated on the supplied competition evidence pack.

7. **Maritime Theme, Responsiveness & Accessibility (Goal 7)**
   - Nautical shipping-lane visual identity with custom corridor boundaries and sonar ripples.
   - Light and Dark maritime theme toggle with persistent state (`localStorage`).
   - Full keyboard navigation (`Space`, `ArrowLeft`, `ArrowRight`, `G`, `T`, `Escape`).
   - Mobile responsive layout verified at 390px (iPhone viewport) with zero horizontal overflow.
   - Full `@media (prefers-reduced-motion: reduce)` compliance.
