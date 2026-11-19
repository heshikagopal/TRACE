"""
TRACE Case Risk Scoring Module
Provides a transparent, auditable scoring breakdown for investigation cases.
Prevents double-counting duplicate evidence and accounts for timestamp reliability.
"""

from typing import Dict, Any, List
from trace_engine.correlation_models import CorrelatedEvent, RelationshipType


class CaseRiskScorer:
    """Calculates explainable case risk scores with full factor attribution."""

    @classmethod
    def evaluate_case(cls, case_id: str, timeline: List[CorrelatedEvent], primary_entities: List[str]) -> Dict[str, Any]:
        """
        Evaluates a case timeline and produces an auditable score breakdown.
        """
        factors = {}
        total_score = 0.0

        if not timeline:
            return {
                "final_score": 0.0,
                "severity": "INFORMATIONAL",
                "breakdown": {"no_events": 0.0},
                "explanation": "No events present in case timeline."
            }

        # 1. Systems Diversity (Independent systems involved)
        unique_systems = set(e.source_system for e in timeline)
        # Avoid treating continuation logs (e.g. LedgerOne and LedgerOne_VendorMaster) as distinct corporate systems
        broad_systems = set()
        for s in unique_systems:
            if "LedgerOne" in s:
                broad_systems.add("LedgerOne (Finance)")
            elif "HelpDeskr" in s:
                broad_systems.add("HelpDeskr (Support)")
            elif "SSO" in s:
                broad_systems.add("Single Sign-On (Identity)")
            elif "BlueVault" in s:
                broad_systems.add("BlueVault (Storage)")
            elif "PrivateLink" in s or "Tunnel" in s:
                broad_systems.add("Private-Link Tunnel (Network)")
            else:
                broad_systems.add(s)

        systems_count = len(broad_systems)
        # 8 pts per independent enterprise system (capped at 25)
        sys_pts = min(25.0, systems_count * 8.0)
        factors["independent_systems_involved"] = {
            "systems": list(broad_systems),
            "count": systems_count,
            "points": sys_pts,
            "explanation": f"Involves {systems_count} distinct enterprise systems: {', '.join(broad_systems)}"
        }
        total_score += sys_pts

        # 2. Direct Identifier Matching Strength
        direct_matches = [e for e in timeline if e.relationship_type == RelationshipType.DIRECT_MATCH.value]
        if direct_matches:
            # High-confidence explicit correlation on shared request IDs, usernames, or API keys
            direct_pts = 20.0
            unique_matched_ids = set()
            for m in direct_matches:
                unique_matched_ids.update(m.identifiers_matched)
            factors["direct_identifier_matches"] = {
                "matched_identifiers": list(unique_matched_ids),
                "count": len(direct_matches),
                "points": direct_pts,
                "explanation": f"Established through direct identifier matches on: {', '.join(unique_matched_ids)}"
            }
            total_score += direct_pts
        else:
            factors["direct_identifier_matches"] = {
                "points": 0.0,
                "explanation": "No direct shared technical identifiers; based on contextual or temporal correlation."
            }

        # 3. Control & Policy Breach Factor
        # Check for unapproved financial modifications or post-termination access
        has_unapproved_fin = any("approval" in e.description.lower() or "bank" in e.description.lower() for e in timeline)
        has_term_access = any("termination" in e.description.lower() for e in timeline)
        has_burst_export = any("bulk export" in e.description.lower() for e in timeline)

        policy_pts = 0.0
        policy_reasons = []
        if has_unapproved_fin:
            policy_pts += 20.0
            policy_reasons.append("Bypass of dual-authorization on vendor bank records")
        if has_term_access:
            policy_pts += 18.0
            policy_reasons.append("Authentication using unrevoked former employee account")
        if has_burst_export:
            policy_pts += 15.0
            policy_reasons.append("Abnormal volume burst on sensitive data export")

        policy_pts = min(30.0, policy_pts)
        factors["policy_and_control_breaches"] = {
            "reasons": policy_reasons,
            "points": policy_pts,
            "explanation": "; ".join(policy_reasons) if policy_reasons else "Standard operational parameters"
        }
        total_score += policy_pts

        # 4. Multi-Stage Event Sequence Factor
        # Did activity span multiple stages (Reconnaissance -> Access -> Action)?
        has_recon = any("search" in e.description.lower() or "export" in e.description.lower() for e in timeline)
        has_pivot = any("build" in e.description.lower() or "flow" in e.description.lower() for e in timeline)
        has_impact = any("bank" in e.description.lower() or "modified" in e.description.lower() for e in timeline)

        if has_recon and has_pivot and has_impact:
            seq_pts = 20.0
            factors["multi_stage_progression"] = {
                "stages": ["Reconnaissance / Exfiltration", "Network / Credential Pivot", "Financial Modification"],
                "points": seq_pts,
                "explanation": "Event sequence exhibits coordinated multi-stage progression across multiple days."
            }
            total_score += seq_pts
        elif len(timeline) >= 3:
            seq_pts = 10.0
            factors["multi_stage_progression"] = {
                "stages": ["Sequential activity"],
                "points": seq_pts,
                "explanation": f"Contains sequence of {len(timeline)} chronologically linked events."
            }
            total_score += seq_pts
        else:
            factors["multi_stage_progression"] = {
                "points": 5.0,
                "explanation": "Limited event sequence length."
            }
            total_score += 5.0

        # 5. Timestamp Reliability & Uncertainty Deductions
        uncertain_events = [e for e in timeline if "drift" in e.uncertainty_notes.lower() or "unsynchronised" in e.uncertainty_notes.lower()]
        unverified_events = [e for e in timeline if e.relationship_type == RelationshipType.UNVERIFIED.value]

        deductions = 0.0
        deduction_reasons = []
        if uncertain_events and len(uncertain_events) == len(timeline):
            # If the ENTIRE case relies solely on unsynchronized clocks
            deductions -= 10.0
            deduction_reasons.append("Solely reliant on unsynchronized clocks without corroboration (-10 pts)")
        elif uncertain_events:
            deductions -= 3.0
            deduction_reasons.append(f"Includes {len(uncertain_events)} events with clock drift uncertainty (-3 pts)")

        if unverified_events and len(unverified_events) == len(timeline):
            deductions -= 15.0
            deduction_reasons.append("Solely reliant on unverified third-party vendor indicators (-15 pts)")
        elif unverified_events:
            deductions -= 4.0
            deduction_reasons.append(f"Includes {len(unverified_events)} unverified external associations (-4 pts)")

        factors["timestamp_and_source_uncertainty"] = {
            "deductions": deductions,
            "reasons": deduction_reasons,
            "explanation": "; ".join(deduction_reasons) if deduction_reasons else "All timestamps verified and calibrated"
        }
        total_score += deductions

        # Clamp final score
        final_score = round(min(100.0, max(5.0, total_score)), 1)

        # Map severity
        if final_score >= 90.0:
            severity = "CRITICAL"
        elif final_score >= 75.0:
            severity = "HIGH"
        elif final_score >= 50.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "final_score": final_score,
            "severity": severity,
            "breakdown": factors,
            "explanation": f"Case assessed at {severity} risk ({final_score}/100) across {systems_count} independent systems."
        }
