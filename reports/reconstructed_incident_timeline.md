# TRACE — Reconstructed Incident Timeline
**Investigation Case File:** CR-26-047 (Harbor & Finch Freight Pvt. Ltd.)  
**Incident Scope:** Dual Incident Analysis (Vendor Master Tampering & Deprovisioning Delay)  
**Investigation Period:** 1 June 2026 – 7 September 2026  

---

## Chronological Attack Progression & Key Milestone Events

| Original Timestamp | Normalised Timestamp (UTC) | Source System | Evidence ID | Factual Event Description & Findings | Relationship Type | Confidence & Known Uncertainty |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| `2026-06-15 14:22` | `2026-06-15T08:52:00Z` | Support Chat | **E13** | Operator pastes active BlueVault customer storage key `bvk-7f3a` into support ticket `TKT-48213` for single customer debugging. | Contextual Association | **Confirmed Fact** (Chat record verified; unencrypted secret). |
| `2026-06-30` | `2026-06-30T23:59:59Z` | HR Roster | **E14** | Official departure date of Rohan Menon (`r.menon`), Accounts Payable clerk. Access credentials remain unrevoked. | Direct Identifier | **Confirmed Fact** (Termination date documented; roster status field corrupted). |
| `11/08/2026 23:14:02` | `2026-08-11T17:44:02Z` | HelpDeskr | **E02** | Targeted credential search for sensitive terms (`bvk-`, `secret`, `password`, `api_key`) across customer support tickets. | Direct Identifier | **Confirmed Fact** (IST timezone offset of -05:30 applied). |
| `11/08/2026 23:30:10` | `2026-08-11T18:00:10Z` | HelpDeskr | **E02** | First of 30 bulk ticket export jobs initiated within a 90-minute window, exfiltrating ticket archives containing credentials. | Direct Identifier | **Confirmed Fact** (Corroborated by E06 invoice overage charges). |
| `1723528800` (Approx) | `2026-08-13T06:00:00Z` | BlueVault | **E05** | Credential `bvk-7f3a` invoked to access 143 distinct customer directories and download vendor bank instruction sheet (`Coastal_Packaging_V0412.pdf`). | Direct Identifier | **High Confidence** (Uncertainty: BlueVault hardware clock was unsynchronized; approximate sequence). |
| `2026-08-13T09:02:00+00:00` | `2026-08-13T09:02:00Z` | SSO | **E03** | Former employee Rohan Menon (`r.menon`) successfully signs in from warehouse kiosk IP `172.16.8.44` 44 days post-termination date. | Direct Identifier | **Confirmed Fact** (SSO event `sso-bb8ab61e08` verified; AP credentials active). |
| `2026-08-21 10:15` | `2026-08-21T04:45:00Z` | External Email | **E12** | TallyBridge issues initial precautionary advisory notice regarding credential anomalies in support environments. | Unverified Context | **Unverified Context** (Vendor self-reported disclosure). |
| `2026-08-28 16:30` | `2026-08-28T11:00:00Z` | External Email | **E16** | TallyBridge issues follow-up confirmation of compromised build server infrastructure and advises credential rotation. | Unverified Context | **Unverified Context** (Vendor self-reported advisory). |
| `2026-08-29T04:12:00Z` | `2026-08-29T04:12:00Z` | PrivateLink | **E15** | Internal network link flow records sustained traffic from host `10.20.4.77` labeled `tb-build-02` (build server) through private tunnel. | Contextual Association | **Confirmed Fact** (Corroborated by OSINT status records E20). |
| `2026-09-03T01:40:15Z` | `2026-09-03T01:40:15Z` | LedgerOne | **E18** | Integration key `key-tb-07` issues HTTP `GET` from build server `10.20.4.77` probing `/v2/vendors/V-0412/bank-details` (Request ID: `req-5f61b0de1`). | Direct Identifier | **Confirmed Fact** (Off-scope endpoint and unauthorized caller host). |
| `2026-09-03T01:42:00Z` | `2026-09-03T01:42:00Z` | LedgerOne | **E18** | Integration key `key-tb-07` queries `/v2/payments/scheduled` from `10.20.4.77`, observing upcoming payment run scheduled for 8 September 2026. | Direct Identifier | **Confirmed Fact** (Financial reconnaissance). |
| `2026-09-03T01:44:30Z` | `2026-09-03T01:44:30Z` | VendorMaster | **E19** | **Attack Execution**: Bank account for Coastal Packaging Ltd (`V-0412`) modified via API (`key-tb-07`) from `10.20.4.77` to `****9083` with no approval reference (`req-5f61b0de8`). | Direct Identifier | **Confirmed Fact** (Change ID `chg-8b9888c39b` matches E18 request `req-5f61b0de8`). |
| `2026-09-08 (Scheduled)` | `2026-09-08T00:00:00Z` | Finance | **E18/E10** | **Pending Diversion**: Scheduled payment batch to Coastal Packaging Ltd. Intervention required before execution to prevent loss of vendor funds. | Temporal Projection | **Actionable Threat** (Immediate payment hold recommended). |
