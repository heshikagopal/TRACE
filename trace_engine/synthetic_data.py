"""
TRACE Synthetic Telemetry Generator
Generates safe, fictional cybersecurity events conforming to TRACE Common Event Schema.
All records are explicitly tagged as SIMULATED to prevent evidence pollution.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import random

# Prefix for all synthetic records to ensure zero confusion with real case evidence
SIMULATION_TAG = "SIMULATED_TEST_LAB"


class SyntheticEventBuilder:
    """Constructs standardized synthetic events adhering to TRACE Common Event Schema."""

    @staticmethod
    def create_sso_event(
        simulation_id: str,
        scenario_id: str,
        user: str,
        timestamp: datetime,
        result: str = "success",
        source_ip: str = "172.16.8.99",
        auth_method: str = "password+totp",
        failure_reason: Optional[str] = None,
        device_id: Optional[str] = "dev-sim-9901",
        expected_classification: str = "BENIGN_SIGNIN",
        config_snapshot: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates a synthetic SSO sign-in event (analogous to E03)."""
        evt_id = f"sim-sso-{uuid.uuid4().hex[:8]}"
        ts_orig = timestamp.isoformat() + "+00:00"

        raw_record = {
            "ts_utc": ts_orig,
            "event_id": evt_id,
            "user": user,
            "source_ip": source_ip,
            "city": "Chennai",
            "auth_method": auth_method,
            "mfa_result": "passed" if result == "success" else "failed",
            "device_id": device_id,
            "result": result,
            "failure_reason": failure_reason,
            "data_source": SIMULATION_TAG
        }

        return {
            "event_id": f"SIM:{evt_id}",
            "original_event_id": evt_id,
            "timestamp": timestamp,
            "timestamp_orig": ts_orig,
            "timezone_assumption": "UTC (Simulated)",
            "source_evidence_id": "E03",
            "system": "SSO",
            "actor": user,
            "actor_type": "user",
            "action": "sso.signin",
            "target": "SSO_Portal",
            "source_ip": source_ip,
            "result": result,
            "details": {
                "city": "Chennai",
                "auth_method": auth_method,
                "mfa_result": "passed" if result == "success" else "failed",
                "device_id": device_id,
                "failure_reason": failure_reason or ""
            },
            "raw_record": raw_record,
            "is_synthetic": True,
            "simulation_id": simulation_id,
            "scenario_id": scenario_id,
            "expected_classification": expected_classification,
            "scenario_configuration": config_snapshot or {}
        }

    @staticmethod
    def create_api_event(
        simulation_id: str,
        scenario_id: str,
        api_key_id: str,
        endpoint: str,
        method: str,
        timestamp: datetime,
        caller_ip: str,
        status: int = 200,
        user_agent: str = "SimClient/2.0",
        records_returned: int = 1,
        expected_classification: str = "BENIGN_API",
        config_snapshot: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates a synthetic LedgerOne API access event (analogous to E01/E18)."""
        req_id = f"sim-req-{uuid.uuid4().hex[:8]}"
        ts_orig = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

        raw_record = {
            "ts_utc": ts_orig,
            "request_id": req_id,
            "api_key_id": api_key_id,
            "caller_ip": caller_ip,
            "user_agent": user_agent,
            "endpoint": endpoint,
            "method": method,
            "records_returned": records_returned,
            "status": status,
            "data_source": SIMULATION_TAG
        }

        return {
            "event_id": f"SIM:{req_id}",
            "original_event_id": req_id,
            "timestamp": timestamp,
            "timestamp_orig": ts_orig,
            "timezone_assumption": "UTC (Simulated)",
            "source_evidence_id": "E18",
            "system": "LedgerOne",
            "actor": api_key_id,
            "actor_type": "integration_key",
            "action": f"api.{method.lower()}",
            "target": endpoint,
            "source_ip": caller_ip,
            "result": str(status),
            "details": {
                "method": method,
                "endpoint": endpoint,
                "user_agent": user_agent,
                "records_returned": records_returned
            },
            "raw_record": raw_record,
            "is_synthetic": True,
            "simulation_id": simulation_id,
            "scenario_id": scenario_id,
            "expected_classification": expected_classification,
            "scenario_configuration": config_snapshot or {}
        }

    @staticmethod
    def create_vendor_change_event(
        simulation_id: str,
        scenario_id: str,
        vendor_id: str,
        vendor_name: str,
        field_changed: str,
        old_val: str,
        new_val: str,
        changed_by: str,
        channel: str,
        timestamp: datetime,
        source_ip: str,
        approval_ref: Optional[str] = None,
        request_id: Optional[str] = None,
        expected_classification: str = "BENIGN_VENDOR_CHANGE",
        config_snapshot: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates a synthetic vendor master change event (analogous to E19)."""
        chg_id = f"sim-chg-{uuid.uuid4().hex[:8]}"
        ts_orig = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

        raw_record = {
            "ts_utc": ts_orig,
            "change_id": chg_id,
            "vendor_id": vendor_id,
            "vendor_name": vendor_name,
            "field": field_changed,
            "old_value": old_val,
            "new_value": new_val,
            "changed_by": changed_by,
            "channel": channel,
            "approval_ref": approval_ref,
            "source_ip": source_ip,
            "request_id": request_id,
            "data_source": SIMULATION_TAG
        }

        return {
            "event_id": f"SIM:{chg_id}",
            "original_event_id": chg_id,
            "timestamp": timestamp,
            "timestamp_orig": ts_orig,
            "timezone_assumption": "UTC (Simulated)",
            "source_evidence_id": "E19",
            "system": "LedgerOne_VendorMaster",
            "actor": changed_by,
            "actor_type": "integration_key" if channel == "API" else "user",
            "action": f"vendor.change.{field_changed}",
            "target": f"{vendor_id} ({vendor_name})",
            "source_ip": source_ip,
            "result": "applied",
            "details": {
                "vendor_id": vendor_id,
                "vendor_name": vendor_name,
                "field": field_changed,
                "old_value": old_val,
                "new_value": new_val,
                "channel": channel,
                "approval_ref": approval_ref or "",
                "request_id": request_id or ""
            },
            "raw_record": raw_record,
            "is_synthetic": True,
            "simulation_id": simulation_id,
            "scenario_id": scenario_id,
            "expected_classification": expected_classification,
            "scenario_configuration": config_snapshot or {}
        }

    @staticmethod
    def create_helpdesk_event(
        simulation_id: str,
        scenario_id: str,
        action: str,
        actor: str,
        timestamp: datetime,
        source_ip: str,
        object_id: str,
        details: Optional[str] = None,
        result: str = "ok",
        expected_classification: str = "BENIGN_HELPDESK",
        config_snapshot: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generates a synthetic HelpDeskr event (analogous to E02)."""
        evt_id = f"sim-hd-{uuid.uuid4().hex[:8]}"
        # Tenant local format DD/MM/YYYY HH:MM:SS
        ts_orig = timestamp.strftime("%d/%m/%Y %H:%M:%S")

        raw_record = {
            "ts_local": ts_orig,
            "event_id": evt_id,
            "actor": actor,
            "actor_type": "user",
            "action": action,
            "object_id": object_id,
            "source_ip": source_ip,
            "result": result,
            "details": details,
            "data_source": SIMULATION_TAG
        }

        return {
            "event_id": f"SIM:{evt_id}",
            "original_event_id": evt_id,
            "timestamp": timestamp,
            "timestamp_orig": ts_orig,
            "timezone_assumption": "IST (Simulated UTC+05:30)",
            "source_evidence_id": "E02",
            "system": "HelpDeskr",
            "actor": actor,
            "actor_type": "user",
            "action": action,
            "target": object_id,
            "source_ip": source_ip,
            "result": result,
            "details": {
                "object_id": object_id,
                "details": details or ""
            },
            "raw_record": raw_record,
            "is_synthetic": True,
            "simulation_id": simulation_id,
            "scenario_id": scenario_id,
            "expected_classification": expected_classification,
            "scenario_configuration": config_snapshot or {}
        }
