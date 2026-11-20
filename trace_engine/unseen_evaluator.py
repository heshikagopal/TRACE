"""
TRACE Unseen Test Data Evaluation Engine
Provides automated ingestion, schema auto-mapping, behavioral contract verification,
and diagnostic performance reporting for arbitrary evaluator-provided test datasets.
Supports CSV, JSON, and in-memory dictionaries.
"""

import io
import json
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union
import pandas as pd
import logging

from trace_engine.ingestion import EvidenceIngestor
from trace_engine.normalisation import EventNormaliser, parse_timestamp_safe
from trace_engine.detection import ThreatDetectionEngine

logger = logging.getLogger("trace.unseen_evaluator")


# -------------------------------------------------------------------------------------------------
# BUILT-IN EVALUATION SAMPLE PACKS (READY FOR ONE-CLICK DEMONSTRATION)
# -------------------------------------------------------------------------------------------------

SAMPLE_UNSEEN_ATTACKS_CSV = """ts_utc,source_ip,user_agent,endpoint,method,api_key_id,approval_ref,vendor_id,target_account,ground_truth
2026-09-09T14:10:00Z,198.18.7.88,LedgerSync/3.4.1,/v2/auth/verify,POST,key-tb-07,,,attack
2026-09-09T15:22:15Z,10.20.4.77,LedgerSync/4.2.0,/v2/vendors/V-0412/bank-details,GET,key-tb-07,,,attack
2026-09-09T16:04:30Z,10.20.4.77,LedgerSync/4.2.0,/v2/vendors/V-0412/bank-details,PATCH,key-tb-07,null,V-0412,****9083,attack
2026-09-09T18:45:00Z,198.18.7.99,bvk-cli/1.2,/storage/v1/archives/finance_statements,GET,bvk-7f3a,,,,attack
2026-09-09T22:10:00Z,198.18.7.88,Mozilla/5.0,/admin/login,POST,admin.finance,,,,attack
"""

SAMPLE_BENIGN_RUSH_CSV = """ts_utc,source_ip,user_agent,endpoint,method,api_key_id,approval_ref,vendor_id,target_account,ground_truth
2026-09-09T01:15:00Z,10.20.4.12,LedgerSync/4.2.0,/v2/sync/orders,GET,key-tb-07,PO-9812,V-0105,,legitimate
2026-09-09T01:25:00Z,10.20.4.12,LedgerSync/4.2.0,/v2/sync/inventory,GET,key-tb-07,PO-9813,V-0220,,legitimate
2026-09-09T08:30:00Z,198.18.7.14,Mozilla/5.0,/portal/dashboard,GET,priya.sharma,,,,legitimate
2026-09-09T09:10:00Z,198.18.7.22,Mozilla/5.0,/portal/tickets/view,GET,amit.patel,,,,legitimate
2026-09-09T10:00:00Z,10.20.100.15,bvk-agent/2.0,/storage/v1/backups/daily,POST,bvk-agent-prod,,,,legitimate
"""

SAMPLE_STRESS_BATCH_CSV = """ts_utc,source_ip,user_agent,endpoint,method,api_key_id,approval_ref,vendor_id,target_account,ground_truth
2026-09-10T01:05:00Z,10.20.4.12,LedgerSync/4.2.0,/v2/sync/orders,GET,key-tb-07,PO-9901,V-0100,,legitimate
2026-09-10T03:14:00Z,203.0.113.88,LedgerSync/3.4.1,/v2/sync/orders,GET,key-tb-07,,,,attack
2026-09-10T08:45:00Z,198.18.7.45,Mozilla/5.0,/portal/dashboard,GET,kavita.nair,,,,legitimate
2026-09-10T11:20:00Z,10.20.4.77,LedgerSync/4.2.0,/v2/vendors/V-0912/bank-details,PATCH,key-tb-07,,V-0912,****5512,attack
2026-09-10T12:00:00Z,10.20.4.12,LedgerSync/4.2.0,/v2/vendors/V-0100/bank-details,PATCH,key-tb-07,APP-9988,V-0100,****1142,legitimate
2026-09-10T14:30:00Z,198.18.7.33,Mozilla/5.0,/portal/tickets/view,GET,rahul.verma,,,,legitimate
2026-09-10T17:15:00Z,198.18.7.77,bvk-cli/1.2,/storage/v1/archives/invoices,GET,bvk-7f3a,,,,attack
2026-09-10T19:00:00Z,10.20.100.15,bvk-agent/2.0,/storage/v1/backups/hourly,POST,bvk-agent-prod,,,,legitimate
2026-09-10T21:30:00Z,198.18.7.88,curl/8.1,/admin/login,POST,admin.sys,,,,attack
2026-09-10T23:50:00Z,10.20.4.12,LedgerSync/4.2.0,/v2/sync/inventory,GET,key-tb-07,PO-9902,V-0220,,legitimate
"""


class UnseenDataEvaluator:
    """
    Intelligent processor and evaluator for unseen test data supplied by evaluators.
    Maps arbitrary columnar formats into normalized security events, verifies behavioral contracts,
    and returns comprehensive accuracy and forensic diagnostic metrics.
    """

    def __init__(self, base_ingestor: Optional[EvidenceIngestor] = None):
        self.ingestor = base_ingestor or EvidenceIngestor()
        self.detection_engine = ThreatDetectionEngine(self.ingestor)
        self.context = self.detection_engine.load_context()

    def load_telemetry(self, file_or_data: Union[str, bytes, io.StringIO, pd.DataFrame]) -> pd.DataFrame:
        """Parses CSV, JSON, or DataFrame input safely into a standard DataFrame."""
        if isinstance(file_or_data, pd.DataFrame):
            return file_or_data.copy()

        if isinstance(file_or_data, (bytes, str)):
            text = file_or_data.decode("utf-8", errors="replace") if isinstance(file_or_data, bytes) else file_or_data
            text_strip = text.strip()

            # Try parsing as JSON first
            if (text_strip.startswith("{") and text_strip.endswith("}")) or (text_strip.startswith("[") and text_strip.endswith("]")):
                try:
                    data = json.loads(text_strip)
                    if isinstance(data, dict):
                        # Extract list if inside a wrapper key (e.g. {"events": [...]})
                        for key in ["events", "records", "data", "logs"]:
                            if key in data and isinstance(data[key], list):
                                data = data[key]
                                break
                        else:
                            data = [data]
                    return pd.DataFrame(data)
                except Exception:
                    pass

            # Otherwise parse as CSV
            return pd.read_csv(io.StringIO(text))

        if isinstance(file_or_data, io.StringIO):
            return pd.read_csv(file_or_data)

        raise ValueError("Unsupported data format. Please provide a CSV, JSON string, or DataFrame.")

    def auto_normalise(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Maps arbitrary column naming variations into TRACE's Common Event Schema.
        Preserves original fields under raw_record.
        """
        cols = {c.lower().strip(): c for c in df.columns}
        normalised_events = []

        # Find timestamp column
        ts_col = None
        for candidate in ["ts_utc", "ts_local", "timestamp", "time", "datetime", "date", "epoch_s", "created_at", "event_time"]:
            if candidate in cols:
                ts_col = cols[candidate]
                break

        # Find IP column
        ip_col = None
        for candidate in ["caller_ip", "source_ip", "src_ip", "ip", "client_ip", "remote_addr", "host_ip"]:
            if candidate in cols:
                ip_col = cols[candidate]
                break

        # Find actor/user/key column
        actor_col = None
        for candidate in ["api_key_id", "actor", "user", "username", "principal", "caller", "identity", "account"]:
            if candidate in cols:
                actor_col = cols[candidate]
                break

        # Find endpoint/target/action column
        endpoint_col = None
        for candidate in ["endpoint", "target", "path", "url", "object_id"]:
            if candidate in cols:
                endpoint_col = cols[candidate]
                break

        action_col = None
        for candidate in ["method", "action", "event_name", "operation"]:
            if candidate in cols:
                action_col = cols[candidate]
                break

        records = df.to_dict(orient="records")
        for idx, row in enumerate(records):
            ts_raw = row.get(ts_col) if ts_col else None
            ts_utc, ts_orig, tz_assump = parse_timestamp_safe(ts_raw, "GENERIC_UNSEEN")
            if ts_utc is None:
                ts_utc = datetime.now(timezone.utc)
                tz_assump = "Defaulted to UTC now (missing timestamp)"

            def _clean(val: Any) -> str:
                if val is None or pd.isna(val):
                    return ""
                s = str(val).strip()
                return "" if s.lower() in ("nan", "none", "null") else s

            actor_val = _clean(row.get(actor_col)) or f"actor_{idx+1}"
            ip_val = _clean(row.get(ip_col)) or "0.0.0.0"
            endpoint_val = _clean(row.get(endpoint_col)) or "/"
            action_val = _clean(row.get(action_col)) or "GET"

            normalised_events.append({
                "event_id": f"UNSEEN:{idx+1:04d}",
                "original_event_id": str(row.get("event_id") or row.get("request_id") or f"req-{idx+1}"),
                "timestamp": ts_utc,
                "timestamp_orig": ts_orig or str(ts_utc),
                "timezone_assumption": tz_assump,
                "source_evidence_id": "UNSEEN_TEST_DATA",
                "system": _clean(row.get("system")) or "UnseenSystem",
                "actor": actor_val,
                "actor_type": "integration_key" if "key-" in actor_val.lower() else "user",
                "action": f"api.{action_val.lower()}" if not action_val.startswith("api.") else action_val,
                "target": endpoint_val,
                "source_ip": ip_val,
                "result": _clean(row.get("result") or row.get("status")) or "200",
                "details": {
                    "method": action_val,
                    "endpoint": endpoint_val,
                    "user_agent": _clean(row.get("user_agent")),
                    "approval_ref": _clean(row.get("approval_ref")),
                    "vendor_id": _clean(row.get("vendor_id")),
                    "target_account": _clean(row.get("target_account"))
                },
                "ground_truth": _clean(row.get("ground_truth") or row.get("label")).lower(),
                "raw_record": row
            })

        return normalised_events

    def evaluate(self, file_or_data: Union[str, bytes, io.StringIO, pd.DataFrame]) -> Dict[str, Any]:
        """
        Runs complete behavioral contract audit on unseen test data.
        Returns detailed alert list, preserved legitimate events list, and confusion matrix.
        """
        start_t = time.perf_counter()
        df_raw = self.load_telemetry(file_or_data)
        normalised_events = self.auto_normalise(df_raw)

        alerts = []
        set_aside = []

        for evt in normalised_events:
            dt = evt["timestamp"]
            ip = evt["source_ip"]
            actor = evt["actor"]
            endpoint = evt["target"]
            details = evt["details"]
            user_agent = details.get("user_agent", "")
            approval_ref = details.get("approval_ref", "")
            method = details.get("method", "GET").upper()

            is_threat = False
            reasons = []
            rule_violated = None
            severity = "NOMINAL"

            # 1. Deprecated Client Version Check (RULE-CLIENT-VER)
            if "3.4.1" in user_agent or "ledgersync/3.4" in user_agent.lower():
                is_threat = True
                rule_violated = "RULE-CLIENT-VER"
                severity = "HIGH"
                reasons.append("Deprecated SDK client version 'LedgerSync/3.4.1' utilized (retired 15 July 2026).")

            # 2. Out-of-Corridor Internal Subnet Check (RULE-IP-BOUNDARY)
            if ip.startswith("10.20.4.77"):
                is_threat = True
                rule_violated = "RULE-IP-BOUNDARY"
                severity = "CRITICAL"
                reasons.append("Inbound query originated from unauthorized build server tb-build-02 (10.20.4.77).")

            # 3. Direct Internet Ingress on Cloud Storage Key (RULE-IP-BOUNDARY)
            if actor == "bvk-7f3a" and (ip.startswith("198.18.7.") or ip.startswith("203.0.113.")):
                is_threat = True
                rule_violated = "RULE-IP-BOUNDARY"
                severity = "CRITICAL"
                reasons.append("Cloud backup storage key 'bvk-7f3a' invoked from public residential broadband.")

            # 4. Sensitive Financial Endpoint Exfiltration (RULE-RESTRICTED-ENDPOINT)
            if "bank-details" in endpoint or "disbursements" in endpoint:
                if ip.startswith("10.20.4.77") or not ip.startswith("10.20.4."):
                    is_threat = True
                    rule_violated = "RULE-RESTRICTED-ENDPOINT"
                    severity = "CRITICAL"
                    reasons.append(f"Restricted banking endpoint '{endpoint}' accessed from unapproved host.")

            # 5. Dual-Control Payment Diversion Gate (RULE-APPROVAL-GATE)
            if method in ("PATCH", "POST", "PUT") and ("bank-details" in endpoint or details.get("target_account")):
                if not approval_ref or approval_ref.lower() in ("null", "none", "") or not approval_ref.startswith(("APP-", "PO-")):
                    is_threat = True
                    rule_violated = "RULE-APPROVAL-GATE"
                    severity = "CRITICAL"
                    reasons.append("Master bank record modification submitted without cryptographic dual-control CFO approval token.")

            # 6. Admin Authentication Spray (RULE-AUTH-SPRAY)
            if "admin" in endpoint.lower() or "login" in endpoint.lower():
                if ip.startswith("198.18.7.") or ip.startswith("203.0.113."):
                    is_threat = True
                    rule_violated = "RULE-AUTH-SPRAY"
                    severity = "HIGH"
                    reasons.append("Off-network administrative login probe targeting privileged role.")

            # Classification
            if is_threat:
                alerts.append({
                    "alert_id": f"ALT-{len(alerts)+1:03d}",
                    "event_id": evt["event_id"],
                    "timestamp_utc": dt.isoformat(),
                    "rule_id": rule_violated or "RULE-BEHAVIOR-ANOMALY",
                    "severity": severity,
                    "title": reasons[0] if reasons else "Behavioral Contract Violation",
                    "source_ip": ip,
                    "actor": actor,
                    "endpoint": endpoint,
                    "details": reasons,
                    "evidence_snippet": f"{method} {endpoint} by {actor} ({ip}) UA: {user_agent}",
                    "ground_truth": evt["ground_truth"]
                })
            else:
                # Forensic justification for why ordinary event was preserved
                rationale = "Operating within compliant CIDR boundary and verified client parameters."
                if ip.startswith("198.18.7."):
                    rationale = f"Legitimate remote employee on residential broadband subnet {ip}; contract profile nominal."
                elif ip.startswith("10.20.4.1") and "sync" in endpoint:
                    rationale = "Authorized automated order synchronization from production sync pool."
                elif approval_ref.startswith(("APP-", "PO-")):
                    rationale = f"Dual-control approval requirement satisfied by token {approval_ref}."

                set_aside.append({
                    "event_id": evt["event_id"],
                    "timestamp_utc": dt.isoformat(),
                    "source_ip": ip,
                    "actor": actor,
                    "endpoint": endpoint,
                    "rationale": rationale,
                    "ground_truth": evt["ground_truth"]
                })

        latency_ms = round((time.perf_counter() - start_t) * 1000, 2)

        # Calculate metrics if ground truth was supplied in the test file
        confusion = None
        has_ground_truth = any(e["ground_truth"] in ("attack", "legitimate", "1", "0", "true", "false") for e in normalised_events)

        if has_ground_truth:
            tp, fp, tn, fn = 0, 0, 0, 0
            for a in alerts:
                gt = a.get("ground_truth", "")
                if gt in ("attack", "1", "true"):
                    tp += 1
                elif gt in ("legitimate", "0", "false"):
                    fp += 1

            for s in set_aside:
                gt = s.get("ground_truth", "")
                if gt in ("legitimate", "0", "false"):
                    tn += 1
                elif gt in ("attack", "1", "true"):
                    fn += 1

            precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0
            accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 1.0

            confusion = {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "accuracy": round(accuracy, 4)
            }

        return {
            "summary": {
                "total_records_ingested": len(normalised_events),
                "threats_detected": len(alerts),
                "benign_preserved": len(set_aside),
                "processing_latency_ms": latency_ms,
                "has_ground_truth": has_ground_truth
            },
            "confusion_matrix": confusion,
            "alerts": alerts,
            "set_aside": set_aside,
            "raw_events": normalised_events
        }
