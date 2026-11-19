"""
TRACE Scenario Templates & Configuration Lab
Declarative test templates for Scenarios A through E with Development and Held-Out evaluation suites.
All records are strictly synthetic and self-contained.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
import uuid
import pandas as pd

from trace_engine.synthetic_data import SyntheticEventBuilder


class ScenarioTemplateEngine:
    """Generates parameterized synthetic event streams for evaluation."""

    # -------------------------------------------------------------------------
    # SCENARIO A: Former Employee Access
    # -------------------------------------------------------------------------
    @staticmethod
    def generate_scenario_a_former_employee(
        is_terminated: bool = True,
        login_success: bool = True,
        source_ip: str = "172.16.8.88",
        days_after_termination: int = 15,
        username: str = "sim.former.clerk",
        full_name: str = "Simulated Former Employee",
        device_id: Optional[str] = "kiosk-sim-01"
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Scenario A: Former employee sign-in attempt.
        Returns (synthetic_events, synthetic_context_dict).
        """
        sim_id = f"SIM-A-{uuid.uuid4().hex[:6]}"
        now = datetime(2026, 9, 5, 10, 0, tzinfo=timezone.utc)
        
        # Determine termination date
        term_date = (now - timedelta(days=days_after_termination)).strftime("%Y-%m-%d") if is_terminated else None
        
        # Synthetic roster row
        roster_row = {
            "employee_id": "HF-SIM-01",
            "username": username,
            "full_name": full_name,
            "department": "Finance",
            "role": "Accounts Payable Clerk",
            "status": "active",  # Retaining the known recordkeeping defect
            "manager": "m.sundar",
            "hire_date": "2023-01-15",
            "termination_date": term_date,
            "notes": "Simulated synthetic test user"
        }
        synthetic_roster = pd.DataFrame([roster_row])

        # Login event
        expected = "RULE-AUTH-001" if (is_terminated and days_after_termination > 1 and login_success) else "BENIGN"
        
        cfg = {
            "is_terminated": is_terminated,
            "login_success": login_success,
            "source_ip": source_ip,
            "days_after_termination": days_after_termination,
            "username": username
        }

        sso_event = SyntheticEventBuilder.create_sso_event(
            simulation_id=sim_id,
            scenario_id="SCENARIO_A",
            user=username,
            timestamp=now,
            result="success" if login_success else "failure",
            source_ip=source_ip,
            failure_reason=None if login_success else "Invalid credentials",
            device_id=device_id,
            expected_classification=expected,
            config_snapshot=cfg
        )

        return [sso_event], {"E14": synthetic_roster}

    # -------------------------------------------------------------------------
    # SCENARIO B: Compromised Integration Credential
    # -------------------------------------------------------------------------
    @staticmethod
    def generate_scenario_b_api_activity(
        is_suspicious_caller: bool = True,
        is_sensitive_endpoint: bool = True,
        api_key_id: str = "key-tb-07",
        caller_ip: str = "10.20.4.77",
        endpoint: str = "/v2/vendors/V-SIM-0412/bank-details",
        method: str = "GET",
        event_count: int = 3,
        user_agent: str = "TallyBridge-Sync/3.5.0"
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Scenario B: Integration API activity.
        Includes options for suspicious build host IP vs legitimate sync IP pool.
        """
        sim_id = f"SIM-B-{uuid.uuid4().hex[:6]}"
        base_time = datetime(2026, 9, 3, 1, 30, tzinfo=timezone.utc)
        events = []

        cfg = {
            "is_suspicious_caller": is_suspicious_caller,
            "is_sensitive_endpoint": is_sensitive_endpoint,
            "api_key_id": api_key_id,
            "caller_ip": caller_ip,
            "endpoint": endpoint,
            "event_count": event_count
        }

        expected = "RULE-API-001" if (caller_ip == "10.20.4.77" and api_key_id == "key-tb-07") else "BENIGN"

        for i in range(event_count):
            t = base_time + timedelta(seconds=i * 45)
            evt = SyntheticEventBuilder.create_api_event(
                simulation_id=sim_id,
                scenario_id="SCENARIO_B",
                api_key_id=api_key_id,
                endpoint=endpoint,
                method=method,
                timestamp=t,
                caller_ip=caller_ip,
                status=200,
                user_agent=user_agent,
                expected_classification=expected,
                config_snapshot=cfg
            )
            events.append(evt)

        return events, {}

    # -------------------------------------------------------------------------
    # SCENARIO C: Vendor Record Modification
    # -------------------------------------------------------------------------
    @staticmethod
    def generate_scenario_c_vendor_modification(
        field_changed: str = "bank_account",
        channel: str = "API",
        has_approval_ref: bool = False,
        approval_ref_val: Optional[str] = None,
        source_ip: str = "10.20.4.77",
        changed_by: str = "key-tb-07",
        vendor_id: str = "V-SIM-0412",
        vendor_name: str = "Simulated Packaging Ltd",
        include_correlated_api_request: bool = True
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Scenario C: Vendor change simulation.
        Can generate unapproved API changes (threat) or approved UI changes (negative test).
        """
        sim_id = f"SIM-C-{uuid.uuid4().hex[:6]}"
        t = datetime(2026, 9, 3, 1, 44, 30, tzinfo=timezone.utc)
        req_id = f"req-sim-{uuid.uuid4().hex[:6]}"
        events = []

        appr = (approval_ref_val or "APR-SIM-1234") if has_approval_ref else None

        # Determine expected classification
        if field_changed == "bank_account":
            if channel == "API":
                expected = "RULE-FIN-001"
            elif not has_approval_ref:
                expected = "RULE-FIN-002"
            else:
                expected = "BENIGN"
        else:
            expected = "BENIGN"

        cfg = {
            "field_changed": field_changed,
            "channel": channel,
            "has_approval_ref": has_approval_ref,
            "source_ip": source_ip,
            "changed_by": changed_by
        }

        # 1. Vendor change event (E19)
        chg_evt = SyntheticEventBuilder.create_vendor_change_event(
            simulation_id=sim_id,
            scenario_id="SCENARIO_C",
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            field_changed=field_changed,
            old_val="****4417",
            new_val="****9083",
            changed_by=changed_by,
            channel=channel,
            timestamp=t,
            source_ip=source_ip,
            approval_ref=appr,
            request_id=req_id if channel == "API" else None,
            expected_classification=expected,
            config_snapshot=cfg
        )
        events.append(chg_evt)

        # 2. Correlating API event if API channel
        if channel == "API" and include_correlated_api_request:
            api_evt = SyntheticEventBuilder.create_api_event(
                simulation_id=sim_id,
                scenario_id="SCENARIO_C",
                api_key_id=changed_by,
                endpoint=f"/v2/vendors/{vendor_id}/bank-details",
                method="PATCH",
                timestamp=t,
                caller_ip=source_ip,
                status=200,
                user_agent="TallyBridge-Sync/3.5.0",
                expected_classification=expected,
                config_snapshot=cfg
            )
            # Match the request_id
            api_evt["event_id"] = f"SIM:{req_id}"
            api_evt["original_event_id"] = req_id
            events.append(api_evt)

        return events, {}

    # -------------------------------------------------------------------------
    # SCENARIO D: Unusual Data Export
    # -------------------------------------------------------------------------
    @staticmethod
    def generate_scenario_d_export_activity(
        is_burst: bool = True,
        include_recon_searches: bool = True,
        export_count: int = 12,
        actor: str = "sim.operator",
        source_ip: str = "198.18.7.41"
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Scenario D: HelpDeskr ticket export and reconnaissance.
        Tests burst vs routine single export.
        """
        sim_id = f"SIM-D-{uuid.uuid4().hex[:6]}"
        base_time = datetime(2026, 8, 11, 23, 10, tzinfo=timezone.utc)
        events = []

        cfg = {
            "is_burst": is_burst,
            "include_recon_searches": include_recon_searches,
            "export_count": export_count,
            "actor": actor,
            "source_ip": source_ip
        }

        # Sub-events: Recon searches
        if include_recon_searches:
            keywords = ["password", "api_key", "secret", "token", "bvk-"]
            for i, kw in enumerate(keywords):
                t = base_time + timedelta(minutes=i)
                search_evt = SyntheticEventBuilder.create_helpdesk_event(
                    simulation_id=sim_id,
                    scenario_id="SCENARIO_D",
                    action="ticket.search",
                    actor=actor,
                    timestamp=t,
                    source_ip=source_ip,
                    object_id=f"TKT-SEARCH-{i+1}",
                    details=kw,
                    expected_classification="RULE-EXP-001",
                    config_snapshot=cfg
                )
                events.append(search_evt)

        # Export events
        exp_time = base_time + timedelta(minutes=20)
        expected_exp = "RULE-EXP-002" if is_burst and export_count >= 5 else "BENIGN"
        
        num_exports = export_count if is_burst else 1
        for j in range(num_exports):
            t = exp_time + timedelta(minutes=j * 2)
            exp_evt = SyntheticEventBuilder.create_helpdesk_event(
                simulation_id=sim_id,
                scenario_id="SCENARIO_D",
                action="ticket.export",
                actor=actor,
                timestamp=t,
                source_ip=source_ip,
                object_id=f"EXP-{j+1001}",
                details=None,
                expected_classification=expected_exp,
                config_snapshot=cfg
            )
            events.append(exp_evt)

        return events, {}

    # -------------------------------------------------------------------------
    # SCENARIO E: Multi-Stage Attack Progression
    # -------------------------------------------------------------------------
    @staticmethod
    def generate_scenario_e_multi_stage(
        include_former_employee: bool = True,
        include_recon: bool = True,
        include_api_pivot: bool = True,
        include_vendor_tamper: bool = True,
        time_delay_hours: int = 12
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Scenario E: Full end-to-end multi-stage simulation spanning multiple enterprise systems.
        Tests cross-system attack progression synthesis (RULE-CORR-001).
        """
        all_events = []
        combined_context = {}

        if include_former_employee:
            evs_a, ctx_a = ScenarioTemplateEngine.generate_scenario_a_former_employee(
                is_terminated=True,
                login_success=True,
                source_ip="172.16.8.55",
                days_after_termination=20
            )
            all_events.extend(evs_a)
            combined_context.update(ctx_a)

        if include_recon:
            evs_d, _ = ScenarioTemplateEngine.generate_scenario_d_export_activity(
                is_burst=True,
                include_recon_searches=True,
                export_count=8
            )
            all_events.extend(evs_d)

        if include_api_pivot:
            evs_b, _ = ScenarioTemplateEngine.generate_scenario_b_api_activity(
                is_suspicious_caller=True,
                is_sensitive_endpoint=True,
                caller_ip="10.20.4.77",
                event_count=3
            )
            all_events.extend(evs_b)

        if include_vendor_tamper:
            evs_c, _ = ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
                field_changed="bank_account",
                channel="API",
                has_approval_ref=False,
                source_ip="10.20.4.77"
            )
            all_events.extend(evs_c)

        # Sort combined events chronologically
        all_events.sort(key=lambda e: e["timestamp"])
        return all_events, combined_context

    # -------------------------------------------------------------------------
    # BENIGN ENTERPRISE BASELINE
    # -------------------------------------------------------------------------
    @staticmethod
    def generate_benign_baseline() -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Generates a comprehensive stream of legitimate enterprise activities spanning
        SSO, LedgerOne API, HelpDeskr, and Vendor Master changes with full compliance.
        """
        events = []
        context = {}
        
        # 1. Active staff login
        evs_a, ctx_a = ScenarioTemplateEngine.generate_scenario_a_former_employee(
            is_terminated=False, login_success=True, source_ip="172.16.8.20", username="v.kumar"
        )
        events.extend(evs_a)
        context.update(ctx_a)
        
        # 2. Legitimate API order sync from approved pool
        evs_b, _ = ScenarioTemplateEngine.generate_scenario_b_api_activity(
            is_suspicious_caller=False, is_sensitive_endpoint=False, caller_ip="10.20.4.11", event_count=5
        )
        events.extend(evs_b)
        
        # 3. Approved vendor address update via Portal
        evs_c, _ = ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
            field_changed="address", channel="UI", has_approval_ref=True, approval_ref_val="APV-2026-9001"
        )
        events.extend(evs_c)
        
        # 4. Routine single ticket resolution
        evs_d, _ = ScenarioTemplateEngine.generate_scenario_d_export_activity(
            is_burst=False, include_recon_searches=False, export_count=1
        )
        events.extend(evs_d)
        
        events.sort(key=lambda e: e["timestamp"])
        return events, context


# -----------------------------------------------------------------------------
# HELD-OUT EVALUATION TEST SUITE
# Variations: Different IPs, altered ordering, missing fields, legitimate lookalikes
# -----------------------------------------------------------------------------
HELD_OUT_EVALUATION_SUITE = [
    {
        "test_name": "HELD_OUT_01_Legitimate_Approved_Bank_Change",
        "description": "Legitimate vendor bank account change via UI with signed dual-authorization APR-8812.",
        "expected_alert_count": 0,
        "generator": lambda: ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
            field_changed="bank_account",
            channel="UI",
            has_approval_ref=True,
            approval_ref_val="APR-8812",
            source_ip="172.16.8.44",
            changed_by="f.dsouza"
        )
    },
    {
        "test_name": "HELD_OUT_02_Normal_Sync_High_Volume_Shipments",
        "description": "Routine nightly sync query from pool IP 10.20.4.14 on /v2/shipments with high volume.",
        "expected_alert_count": 0,
        "generator": lambda: ScenarioTemplateEngine.generate_scenario_b_api_activity(
            is_suspicious_caller=False,
            is_sensitive_endpoint=False,
            api_key_id="key-tb-07",
            caller_ip="10.20.4.14",
            endpoint="/v2/shipments",
            event_count=10,
            user_agent="TallyBridge-Sync/3.5.0"
        )
    },
    {
        "test_name": "HELD_OUT_03_Former_Employee_Failed_Login",
        "description": "Former employee sign-in attempt with incorrect password (authentication failure).",
        "expected_alert_count": 1,
        "expected_rule": "RULE-AUTH-001",
        "generator": lambda: ScenarioTemplateEngine.generate_scenario_a_former_employee(
            is_terminated=True,
            login_success=False,
            source_ip="198.18.99.55",
            days_after_termination=10
        )
    },
    {
        "test_name": "HELD_OUT_04_Active_Employee_Normal_Kiosk_Access",
        "description": "Currently employed warehouse worker signing into kiosk normally.",
        "expected_alert_count": 0,
        "generator": lambda: ScenarioTemplateEngine.generate_scenario_a_former_employee(
            is_terminated=False,
            login_success=True,
            source_ip="172.16.8.20",
            days_after_termination=0,
            username="sim.active.worker"
        )
    },
    {
        "test_name": "HELD_OUT_05_Routine_Single_Tuesday_Export",
        "description": "Standard weekly service review export (single export, no reconnaissance).",
        "expected_alert_count": 0,
        "generator": lambda: ScenarioTemplateEngine.generate_scenario_d_export_activity(
            is_burst=False,
            include_recon_searches=False,
            export_count=1,
            actor="s.iyer",
            source_ip="172.16.8.15"
        )
    },
    {
        "test_name": "HELD_OUT_06_Unapproved_Vendor_Contact_Update",
        "description": "Updating contact email and phone without approval reference (benign procedural update).",
        "expected_alert_count": 0,
        "generator": lambda: ScenarioTemplateEngine.generate_scenario_c_vendor_modification(
            field_changed="contact_email",
            channel="UI",
            has_approval_ref=False,
            source_ip="172.16.8.30",
            changed_by="p.shah"
        )
    }
]
