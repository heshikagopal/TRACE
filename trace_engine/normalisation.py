"""
TRACE Normalisation Module (Optimized)
Standardises heterogeneous logs from LedgerOne, HelpDeskr, SSO, BlueVault, Flow Logs, and Vendor Change Logs
into a unified Common Event Schema without discarding original timestamps or raw fields.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import pandas as pd
import logging

logger = logging.getLogger("trace.normalisation")

IST_OFFSET = timedelta(hours=5, minutes=30)
IST_TZ = timezone(IST_OFFSET, name="IST")


def parse_timestamp_safe(ts_val: Any, source_type: str) -> tuple[Optional[datetime], str, str]:
    """
    Parses timestamp safely, returning (normalised_utc_datetime, original_ts_str, timezone_assumption).
    Preserves original timestamp string verbatim.
    """
    orig_str = str(ts_val) if ts_val is not None else ""
    if orig_str == "" or orig_str == "nan" or orig_str == "None":
        return None, "", "Missing timestamp"

    try:
        if source_type in ("E01", "E18"):
            # ISO UTC format: 2026-06-03T00:31:22Z
            dt = datetime.fromisoformat(orig_str.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc), orig_str, "UTC (source standard)"

        elif source_type in ("E02",):
            # Tenant local time (IST, DD/MM/YYYY HH:MM:SS)
            dt_naive = datetime.strptime(orig_str.strip(), "%d/%m/%Y %H:%M:%S")
            dt_ist = dt_naive.replace(tzinfo=IST_TZ)
            return dt_ist.astimezone(timezone.utc), orig_str, "IST (UTC+05:30, converted to UTC)"

        elif source_type in ("E13",):
            # Chat local time (IST, YYYY-MM-DD HH:MM)
            dt_naive = datetime.strptime(orig_str.strip(), "%Y-%m-%d %H:%M")
            dt_ist = dt_naive.replace(tzinfo=IST_TZ)
            return dt_ist.astimezone(timezone.utc), orig_str, "IST (UTC+05:30, converted to UTC)"

        elif source_type in ("E03",):
            # SSO UTC format: 2026-06-01T02:30:21+00:00
            dt = datetime.fromisoformat(orig_str)
            return dt.astimezone(timezone.utc), orig_str, "UTC (source explicit offset +00:00)"

        elif source_type in ("E05",):
            # Unix Epoch seconds. Note: BlueVault clock is unverified / unsynchronized!
            epoch_val = float(orig_str)
            dt = datetime.fromtimestamp(epoch_val, tz=timezone.utc)
            return dt, orig_str, "Unix Epoch (WARNING: Unsynchronised BlueVault clock; subject to drift)"

        elif source_type in ("E15", "E19"):
            # UTC format: 2026-06-03T00:00:06Z or 2026-06-03T07:22:17Z
            dt = datetime.fromisoformat(orig_str.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc), orig_str, "UTC (source standard)"

        else:
            dt = pd.to_datetime(orig_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.to_pydatetime(), orig_str, "Assumed UTC (inferred fallback)"

    except Exception as e:
        return None, orig_str, f"Unparseable ({e})"


class EventNormaliser:
    """Fast vectorized/record-level normalisation into a unified Common Event Schema."""

    @staticmethod
    def normalise_e01_e18_ledgerone(df: pd.DataFrame, source_id: str = "E01") -> List[Dict[str, Any]]:
        events = []
        records = df.to_dict(orient="records")
        for row in records:
            ts_utc, ts_orig, tz_assump = parse_timestamp_safe(row.get("ts_utc"), source_id)
            req_id = str(row.get("request_id") or "")
            key_id = str(row.get("api_key_id") or "")
            actor_type = "integration_key" if key_id else "unknown"
            method = str(row.get("method") or "GET")
            endpoint = str(row.get("endpoint") or "")

            events.append({
                "event_id": f"{source_id}:{req_id}",
                "original_event_id": req_id,
                "timestamp": ts_utc,
                "timestamp_orig": ts_orig,
                "timezone_assumption": tz_assump,
                "source_evidence_id": source_id,
                "system": "LedgerOne",
                "actor": key_id,
                "actor_type": actor_type,
                "action": f"api.{method.lower()}",
                "target": endpoint,
                "source_ip": str(row.get("caller_ip") or ""),
                "result": str(row.get("status") or ""),
                "details": {
                    "method": method,
                    "endpoint": endpoint,
                    "user_agent": str(row.get("user_agent") or ""),
                    "records_returned": row.get("records_returned", 0)
                },
                "raw_record": row
            })
        return events

    @staticmethod
    def normalise_e02_helpdeskr(df: pd.DataFrame) -> List[Dict[str, Any]]:
        events = []
        records = df.to_dict(orient="records")
        for row in records:
            ts_utc, ts_orig, tz_assump = parse_timestamp_safe(row.get("ts_local"), "E02")
            evt_id = str(row.get("event_id") or "")
            actor = str(row.get("actor") or "")
            actor_type = str(row.get("actor_type") or "user")
            action = str(row.get("action") or "")
            obj_id = str(row.get("object_id") or "")
            details_val = row.get("details")
            details_str = str(details_val) if pd.notna(details_val) else ""

            events.append({
                "event_id": f"E02:{evt_id}",
                "original_event_id": evt_id,
                "timestamp": ts_utc,
                "timestamp_orig": ts_orig,
                "timezone_assumption": tz_assump,
                "source_evidence_id": "E02",
                "system": "HelpDeskr",
                "actor": actor,
                "actor_type": actor_type,
                "action": action,
                "target": obj_id,
                "source_ip": str(row.get("source_ip") or ""),
                "result": str(row.get("result") or ""),
                "details": {
                    "object_id": obj_id,
                    "details": details_str
                },
                "raw_record": row
            })
        return events

    @staticmethod
    def normalise_e03_sso(df: pd.DataFrame) -> List[Dict[str, Any]]:
        events = []
        records = df.to_dict(orient="records")
        for row in records:
            ts_utc, ts_orig, tz_assump = parse_timestamp_safe(row.get("ts_utc"), "E03")
            evt_id = str(row.get("event_id") or "")
            user = str(row.get("user") or "")
            result = str(row.get("result") or "")
            fail_reason = row.get("failure_reason")

            events.append({
                "event_id": f"E03:{evt_id}",
                "original_event_id": evt_id,
                "timestamp": ts_utc,
                "timestamp_orig": ts_orig,
                "timezone_assumption": tz_assump,
                "source_evidence_id": "E03",
                "system": "SSO",
                "actor": user,
                "actor_type": "user",
                "action": "sso.signin",
                "target": "SSO_Portal",
                "source_ip": str(row.get("source_ip") or ""),
                "result": result,
                "details": {
                    "city": str(row.get("city") or ""),
                    "auth_method": str(row.get("auth_method") or ""),
                    "mfa_result": str(row.get("mfa_result") or ""),
                    "device_id": str(row.get("device_id") or ""),
                    "failure_reason": str(fail_reason) if pd.notna(fail_reason) else ""
                },
                "raw_record": row
            })
        return events

    @staticmethod
    def normalise_e05_bluevault(df: pd.DataFrame) -> List[Dict[str, Any]]:
        events = []
        records = df.to_dict(orient="records")
        for row in records:
            ts_utc, ts_orig, tz_assump = parse_timestamp_safe(row.get("epoch_s"), "E05")
            evt_id = str(row.get("event_id") or "")
            principal = str(row.get("principal") or "")
            action = f"storage.{str(row.get('action') or '').lower()}"
            path = str(row.get("path") or "")
            actor_type = "key" if principal.startswith("key:") else ("user" if principal.startswith("user:") else "unknown")

            events.append({
                "event_id": f"E05:{evt_id}",
                "original_event_id": evt_id,
                "timestamp": ts_utc,
                "timestamp_orig": ts_orig,
                "timezone_assumption": tz_assump,
                "source_evidence_id": "E05",
                "system": "BlueVault",
                "actor": principal,
                "actor_type": actor_type,
                "action": action,
                "target": path,
                "source_ip": str(row.get("source_ip") or ""),
                "result": str(row.get("result") or ""),
                "details": {
                    "path": path,
                    "bytes": row.get("bytes", 0)
                },
                "raw_record": row
            })
        return events

    @staticmethod
    def normalise_e15_flow_log(df: pd.DataFrame) -> List[Dict[str, Any]]:
        events = []
        records = df.to_dict(orient="records")
        for row in records:
            ts_utc, ts_orig, tz_assump = parse_timestamp_safe(row.get("ts_utc"), "E15")
            flow_id = str(row.get("flow_id") or "")
            src_ip = str(row.get("src_ip") or "")
            src_label = str(row.get("src_label") or "")

            events.append({
                "event_id": f"E15:{flow_id}",
                "original_event_id": flow_id,
                "timestamp": ts_utc,
                "timestamp_orig": ts_orig,
                "timezone_assumption": tz_assump,
                "source_evidence_id": "E15",
                "system": "PrivateLinkTunnel",
                "actor": f"{src_label} ({src_ip})" if src_label else src_ip,
                "actor_type": "network_host",
                "action": "network.flow",
                "target": f"{str(row.get('dst_system') or '')}:{row.get('dst_port', '')}",
                "source_ip": src_ip,
                "result": str(row.get("result") or ""),
                "details": {
                    "src_label": src_label,
                    "bytes_out": row.get("bytes_out", 0),
                    "bytes_in": row.get("bytes_in", 0),
                    "tunnel_id": str(row.get("tunnel_id") or "")
                },
                "raw_record": row
            })
        return events

    @staticmethod
    def normalise_e19_vendor_changes(df: pd.DataFrame) -> List[Dict[str, Any]]:
        events = []
        records = df.to_dict(orient="records")
        for row in records:
            ts_utc, ts_orig, tz_assump = parse_timestamp_safe(row.get("ts_utc"), "E19")
            chg_id = str(row.get("change_id") or "")
            vendor_id = str(row.get("vendor_id") or "")
            vendor_name = str(row.get("vendor_name") or "")
            field_name = str(row.get("field") or "")
            changed_by = str(row.get("changed_by") or "")
            channel = str(row.get("channel") or "")
            appr = row.get("approval_ref")
            appr_str = str(appr) if pd.notna(appr) else ""

            events.append({
                "event_id": f"E19:{chg_id}",
                "original_event_id": chg_id,
                "timestamp": ts_utc,
                "timestamp_orig": ts_orig,
                "timezone_assumption": tz_assump,
                "source_evidence_id": "E19",
                "system": "LedgerOne_VendorMaster",
                "actor": changed_by,
                "actor_type": "integration_key" if channel == "API" else "user",
                "action": f"vendor.change.{field_name}",
                "target": f"{vendor_id} ({vendor_name})",
                "source_ip": str(row.get("source_ip") or ""),
                "result": "applied",
                "details": {
                    "vendor_id": vendor_id,
                    "vendor_name": vendor_name,
                    "field": field_name,
                    "old_value": str(row.get("old_value") or ""),
                    "new_value": str(row.get("new_value") or ""),
                    "channel": channel,
                    "approval_ref": appr_str,
                    "request_id": str(row.get("request_id") or "") if pd.notna(row.get("request_id")) else ""
                },
                "raw_record": row
            })
        return events


def load_and_normalise_all(ingestor) -> pd.DataFrame:
    """Ingests and normalises all core event files into a unified DataFrame."""
    normaliser = EventNormaliser()
    all_events = []

    # E01 LedgerOne
    try:
        df_e01 = ingestor.load_csv("E01")
        all_events.extend(normaliser.normalise_e01_e18_ledgerone(df_e01, "E01"))
    except Exception as e:
        logger.warning(f"Skipping E01: {e}")

    # E18 LedgerOne Continued
    try:
        df_e18 = ingestor.load_csv("E18")
        all_events.extend(normaliser.normalise_e01_e18_ledgerone(df_e18, "E18"))
    except Exception as e:
        logger.warning(f"Skipping E18: {e}")

    # E02 HelpDeskr
    try:
        df_e02 = ingestor.load_csv("E02")
        all_events.extend(normaliser.normalise_e02_helpdeskr(df_e02))
    except Exception as e:
        logger.warning(f"Skipping E02: {e}")

    # E03 SSO
    try:
        df_e03 = ingestor.load_csv("E03")
        all_events.extend(normaliser.normalise_e03_sso(df_e03))
    except Exception as e:
        logger.warning(f"Skipping E03: {e}")

    # E05 BlueVault
    try:
        df_e05 = ingestor.load_csv("E05")
        all_events.extend(normaliser.normalise_e05_bluevault(df_e05))
    except Exception as e:
        logger.warning(f"Skipping E05: {e}")

    # E15 Flow Logs
    try:
        df_e15 = ingestor.load_csv("E15")
        all_events.extend(normaliser.normalise_e15_flow_log(df_e15))
    except Exception as e:
        logger.warning(f"Skipping E15: {e}")

    # E19 Vendor Changes
    try:
        df_e19 = ingestor.load_csv("E19")
        all_events.extend(normaliser.normalise_e19_vendor_changes(df_e19))
    except Exception as e:
        logger.warning(f"Skipping E19: {e}")

    if not all_events:
        return pd.DataFrame()

    df_norm = pd.DataFrame(all_events)
    df_norm.sort_values(by="timestamp", inplace=True)
    df_norm.reset_index(drop=True, inplace=True)
    return df_norm
