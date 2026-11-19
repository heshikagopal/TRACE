"""
TRACE Evidence Ingestion Module
Handles loading, metadata extraction, and source-specific parsing for all 20 CRIMEATHON'26 evidence files (E01-E20).
Preserves source integrity and extracts structured data without discarding original records.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
import pandas as pd
from pypdf import PdfReader

logger = logging.getLogger("trace.ingestion")

EVIDENCE_CATALOG = {
    "E01": {
        "filename": "E01_ledgerone_api_access.csv",
        "format": "CSV",
        "system": "LedgerOne (Finance API)",
        "period": "3 Jun to 31 Aug 2026",
        "time_basis": "UTC",
        "reliability": "Older data purged (>90 days). Time in UTC.",
        "investigative_use": "Baseline API usage, key attribution, endpoint access patterns."
    },
    "E02": {
        "filename": "E02_helpdeskr_audit_log.csv",
        "format": "CSV",
        "system": "HelpDeskr (Support Tickets)",
        "period": "3 Jun to 31 Aug 2026",
        "time_basis": "IST (Tenant local time, UTC+05:30)",
        "reliability": "Complete audit trail.",
        "investigative_use": "Customer support interactions, credential searches, bulk ticket exports."
    },
    "E03": {
        "filename": "E03_sso_signin_log.csv",
        "format": "CSV",
        "system": "SSO (IT Single Sign-On)",
        "period": "1 Jun to 31 Aug 2026",
        "time_basis": "UTC",
        "reliability": "Device field blank before 20 June 2026.",
        "investigative_use": "Staff authentication events, terminated employee logins, MFA status."
    },
    "E04": {
        "filename": "E04_connected_software_register.json",
        "format": "JSON",
        "system": "IT Integration Register",
        "period": "Current snapshot (Sep 2026)",
        "time_basis": "UTC dates",
        "reliability": "Current state only; change history not retained.",
        "investigative_use": "Authorised integrations, credential IDs, permissions, token lifespans."
    },
    "E05": {
        "filename": "E05_bluevault_access_log.csv",
        "format": "CSV",
        "system": "BlueVault (Shared Storage)",
        "period": "3 Jun to 31 Aug 2026",
        "time_basis": "Unix Epoch (Seconds)",
        "reliability": "Unsynchronised system clock; some client IP addresses missing.",
        "investigative_use": "Document and statement access, storage access key tracking."
    },
    "E06": {
        "filename": "E06_billing_alert_and_invoice.pdf",
        "format": "PDF",
        "system": "Finance / HelpDeskr Billing",
        "period": "Aug 2026",
        "time_basis": "IST",
        "reliability": "Official billing documents.",
        "investigative_use": "Corroboration of unauthorized bulk export activity in HelpDeskr."
    },
    "E07": {
        "filename": "E07_onboarding_review_file.pdf",
        "format": "PDF",
        "system": "Finance IT Due Diligence",
        "period": "Jun 2024",
        "time_basis": "Calendar dates",
        "reliability": "Vendor answers were self-reported without independent verification.",
        "investigative_use": "TallyBridge third-party assessment, scope gaps, missed annual review."
    },
    "E08": {
        "filename": "E08_contract_excerpt.pdf",
        "format": "PDF",
        "system": "Legal Contract (MSA)",
        "period": "Effective 10 Jun 2024",
        "time_basis": "Legal text",
        "reliability": "Selected clauses only as provided by Legal.",
        "investigative_use": "Contractual security commitments, incident notification obligations."
    },
    "E09": {
        "filename": "E09_risk_register_extract.xlsx",
        "format": "Excel",
        "system": "Finance and IT Risk Management",
        "period": "Current state",
        "time_basis": "Calendar dates",
        "reliability": "Some entries overdue for review (e.g., R-018 overdue since April 2026).",
        "investigative_use": "Known corporate risk controls, staff deprovisioning weaknesses."
    },
    "E10": {
        "filename": "E10_it_security_policy_v2_1.pdf",
        "format": "PDF",
        "system": "IT Policy Document",
        "period": "Effective 1 Jan 2025",
        "time_basis": "Policy version 2.1",
        "reliability": "Official company policy.",
        "investigative_use": "Baseline compliance rules for integration credentials and vendor modifications."
    },
    "E11": {
        "filename": "E11_internal_audit_report_IA_2025_09.pdf",
        "format": "PDF",
        "system": "Internal Audit Report",
        "period": "Sep 2025",
        "time_basis": "Audit findings as of Sep 2025",
        "reliability": "Formal internal audit report.",
        "investigative_use": "Historical identification of unrevoked accounts and unmonitored API keys."
    },
    "E12": {
        "filename": "E12_email_notice.pdf",
        "format": "PDF",
        "system": "External Communication",
        "period": "21 Aug 2026",
        "time_basis": "IST",
        "reliability": "Unverified vendor notice.",
        "investigative_use": "Early notification from TallyBridge regarding precautionary update."
    },
    "E13": {
        "filename": "E13_support_team_chat_export.json",
        "format": "JSON",
        "system": "Support Team Internal Chat",
        "period": "Jun to Aug 2026",
        "time_basis": "Local time (IST)",
        "reliability": "Partial export (selected channels; DMs excluded).",
        "investigative_use": "Context on operational practices, ticket credentials, customer issues."
    },
    "E14": {
        "filename": "E14_staff_roster.csv",
        "format": "CSV",
        "system": "HR Staff Directory",
        "period": "Current snapshot",
        "time_basis": "Calendar dates (YYYY-MM-DD)",
        "reliability": "Maintained manually; status column uniformly says 'active' despite termination dates.",
        "investigative_use": "Employment verification, role determination, termination date cross-checks."
    },
    "E15": {
        "filename": "E15_network_link_flow_log.csv",
        "format": "CSV",
        "system": "Private-Link Network Gateway",
        "period": "3 Jun to 31 Aug 2026",
        "time_basis": "UTC",
        "reliability": "Source host labels supplied by external party; unverified.",
        "investigative_use": "Network flow monitoring across TallyBridge link (10.20.4.0/24)."
    },
    "E16": {
        "filename": "E16_followup_email_notice.pdf",
        "format": "PDF",
        "system": "External Communication",
        "period": "28 Aug 2026",
        "time_basis": "IST",
        "reliability": "Unverified vendor update.",
        "investigative_use": "Vendor disclosure of credential exposure and attached indicators."
    },
    "E17": {
        "filename": "E17_indicator_list.csv",
        "format": "CSV",
        "system": "External Threat Intelligence",
        "period": "Aug 2026",
        "time_basis": "Calendar dates",
        "reliability": "Prepared by outside company; unverified indicators.",
        "investigative_use": "Indicators of compromise (IPs, retired keys, user-agents) for cross-matching."
    },
    "E18": {
        "filename": "E18_ledgerone_api_access_1_to_7_sep.csv",
        "format": "CSV",
        "system": "LedgerOne (Finance API Continuation)",
        "period": "1 to 7 Sep 2026",
        "time_basis": "UTC",
        "reliability": "Direct system log; complete for period.",
        "investigative_use": "Detection of unauthorized bank detail changes and reconnaissance."
    },
    "E19": {
        "filename": "E19_vendor_master_change_log.csv",
        "format": "CSV",
        "system": "LedgerOne (Vendor Master Audit Log)",
        "period": "3 Jun to 7 Sep 2026",
        "time_basis": "UTC",
        "reliability": "Direct system log; links to E18 by request_id.",
        "investigative_use": "Tracking vendor modifications (bank account, payment terms, approvals)."
    },
    "E20": {
        "filename": "E20_public_records_pack.pdf",
        "format": "PDF",
        "system": "Public OSINT Records",
        "period": "Saved 2 Sep 2026",
        "time_basis": "Various",
        "reliability": "Public snapshots collected by Finance IT; unverified.",
        "investigative_use": "Corroboration of build server names (tb-build-02), IP allocations, release timelines."
    }
}


class EvidenceIngestor:
    """Manages loading and parsing of all evidence files."""

    def __init__(self, base_dir: str = "data/original"):
        self.base_dir = base_dir
        self.catalog = EVIDENCE_CATALOG

    def get_inventory(self) -> List[Dict[str, Any]]:
        """Generates a complete metadata inventory of available evidence files."""
        inventory = []
        for eid, meta in sorted(self.catalog.items()):
            path = os.path.join(self.base_dir, meta["filename"])
            exists = os.path.exists(path)
            size = os.path.getsize(path) if exists else 0
            
            entry = {
                "evidence_id": eid,
                "filename": meta["filename"],
                "format": meta["format"],
                "system": meta["system"],
                "period": meta["period"],
                "time_basis": meta["time_basis"],
                "reliability": meta["reliability"],
                "investigative_use": meta["investigative_use"],
                "exists": exists,
                "size_bytes": size,
                "rows_or_pages": 0,
                "columns_or_sections": []
            }

            if exists:
                ext = meta["format"].lower()
                if ext == "csv":
                    try:
                        df_head = pd.read_csv(path, nrows=1)
                        entry["columns_or_sections"] = list(df_head.columns)
                        with open(path, "r", encoding="utf-8", errors="ignore") as fp:
                            entry["rows_or_pages"] = max(0, sum(1 for _ in fp) - 1)
                    except Exception as e:
                        entry["error"] = str(e)
                elif ext == "json":
                    try:
                        with open(path, "r", encoding="utf-8") as fp:
                            data = json.load(fp)
                        if isinstance(data, dict):
                            entry["columns_or_sections"] = list(data.keys())
                            if "integrations" in data:
                                entry["rows_or_pages"] = len(data["integrations"])
                            elif "messages" in data:
                                entry["rows_or_pages"] = len(data["messages"])
                        elif isinstance(data, list):
                            entry["rows_or_pages"] = len(data)
                            if data:
                                entry["columns_or_sections"] = list(data[0].keys())
                    except Exception as e:
                        entry["error"] = str(e)
                elif ext == "pdf":
                    try:
                        reader = PdfReader(path)
                        entry["rows_or_pages"] = len(reader.pages)
                        entry["columns_or_sections"] = [f"Page {i+1}" for i in range(len(reader.pages))]
                    except Exception as e:
                        entry["error"] = str(e)
                elif ext == "excel":
                    try:
                        sheets, rows = self.read_excel_extract(path)
                        entry["rows_or_pages"] = max(0, len(rows) - 1)
                        entry["columns_or_sections"] = rows[0] if rows else []
                    except Exception as e:
                        entry["error"] = str(e)

            inventory.append(entry)
        return inventory

    def load_csv(self, evidence_id: str) -> pd.DataFrame:
        """Loads a CSV evidence file as a pandas DataFrame."""
        if evidence_id not in self.catalog:
            raise ValueError(f"Unknown evidence ID: {evidence_id}")
        meta = self.catalog[evidence_id]
        path = os.path.join(self.base_dir, meta["filename"])
        if not os.path.exists(path):
            raise FileNotFoundError(f"Evidence file missing: {path}")
        return pd.read_csv(path)

    def load_json(self, evidence_id: str) -> Dict[str, Any]:
        """Loads a JSON evidence file."""
        if evidence_id not in self.catalog:
            raise ValueError(f"Unknown evidence ID: {evidence_id}")
        meta = self.catalog[evidence_id]
        path = os.path.join(self.base_dir, meta["filename"])
        if not os.path.exists(path):
            raise FileNotFoundError(f"Evidence file missing: {path}")
        with open(path, "r", encoding="utf-8") as fp:
            return json.load(fp)

    def load_pdf(self, evidence_id: str) -> Dict[str, Any]:
        """Extracts text and page-level metadata from a PDF evidence file."""
        if evidence_id not in self.catalog:
            raise ValueError(f"Unknown evidence ID: {evidence_id}")
        meta = self.catalog[evidence_id]
        path = os.path.join(self.base_dir, meta["filename"])
        if not os.path.exists(path):
            raise FileNotFoundError(f"Evidence file missing: {path}")
        
        reader = PdfReader(path)
        pages_content = []
        for i, page in enumerate(reader.pages):
            pages_content.append({
                "page_number": i + 1,
                "text": page.extract_text() or ""
            })
        return {
            "evidence_id": evidence_id,
            "filename": meta["filename"],
            "total_pages": len(reader.pages),
            "pages": pages_content
        }

    def read_excel_extract(self, path: str):
        """
        Parses Excel (.xlsx) files using pure Python stdlib zipfile/xml.
        Ensures zero-dependency resilience in environments where openpyxl is optional.
        """
        import zipfile
        import xml.etree.ElementTree as ET

        with zipfile.ZipFile(path) as z:
            strings = []
            if 'xl/sharedStrings.xml' in z.namelist():
                tree = ET.fromstring(z.read('xl/sharedStrings.xml'))
                for si in tree.findall('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}si'):
                    text = ''.join([t.text for t in si.findall('.//{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t') if t.text])
                    strings.append(text)
            
            wb = ET.fromstring(z.read('xl/workbook.xml'))
            sheets = []
            for s in wb.findall('.//{http://schemas.openxmlformats.org/spreadsheetml/2006/main}sheet'):
                sheets.append((s.attrib.get('name', ''), s.attrib.get('sheetId', '')))
            
            sheet1 = ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
            rows = []
            for r in sheet1.findall('.//{http://schemas.openxmlformats.org/spreadsheetml/2006/main}row'):
                row_vals = []
                for c in r.findall('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}c'):
                    t = c.attrib.get('t')
                    v = c.find('{http://schemas.openxmlformats.org/spreadsheetml/2006/main}v')
                    val = v.text if v is not None else ''
                    if t == 's' and val != '':
                        try:
                            val = strings[int(val)]
                        except (IndexError, ValueError):
                            pass
                    row_vals.append(val)
                rows.append(row_vals)
            return sheets, rows

    def load_risk_register(self) -> pd.DataFrame:
        """Loads E09 risk register into a structured DataFrame."""
        meta = self.catalog["E09"]
        path = os.path.join(self.base_dir, meta["filename"])
        sheets, rows = self.read_excel_extract(path)
        if not rows:
            return pd.DataFrame()
        headers = rows[0]
        data = rows[1:]
        # Pad data if needed
        norm_data = [r + [''] * (len(headers) - len(r)) for r in data]
        return pd.DataFrame(norm_data, columns=headers)
