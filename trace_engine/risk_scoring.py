"""
TRACE Risk Scoring Engine
Calculates objective, transparent risk scores (0-100) based on asset criticality,
channel context, authorization status, and evidence verification strength.
"""

from typing import Dict, Any, Optional


class RiskScoreCalculator:
    """Calculates explainable risk scores without opaque black-box heuristics."""

    ASSET_WEIGHTS = {
        "payment_instruction": 35.0,
        "vendor_bank_account": 35.0,
        "identity_credential": 30.0,
        "storage_access_key": 28.0,
        "customer_document": 22.0,
        "support_ticket": 18.0,
        "general_telemetry": 10.0
    }

    SEVERITY_THRESHOLDS = [
        (90.0, "CRITICAL"),
        (75.0, "HIGH"),
        (50.0, "MEDIUM"),
        (25.0, "LOW"),
        (0.0, "INFORMATIONAL")
    ]

    @classmethod
    def calculate(
        cls,
        asset_type: str,
        is_success: bool = True,
        is_api_channel: bool = False,
        missing_approval: bool = False,
        unusual_network_source: bool = False,
        volume_burst: bool = False,
        evidence_confidence: str = "Confirmed Fact"
    ) -> tuple[float, str]:
        """
        Computes (risk_score, severity) based on observable factual attributes.
        Returns a score clamped to [0.0, 100.0] and an assigned severity rating.
        """
        base = cls.ASSET_WEIGHTS.get(asset_type, 15.0)

        score = base

        # Impact factors
        if is_success:
            score += 20.0
        else:
            # Failed attempt indicates blocked or thwarted action
            score += 5.0

        if is_api_channel:
            score += 15.0

        if missing_approval:
            score += 20.0

        if unusual_network_source:
            score += 15.0

        if volume_burst:
            score += 15.0

        # Confidence weighting: unverified third-party indicators do not artificially inflate certainty
        confidence_multipliers = {
            "Confirmed Fact": 1.0,
            "High Confidence": 0.95,
            "Corroborated Intelligence": 0.85,
            "Unverified Indicator": 0.70
        }
        multiplier = confidence_multipliers.get(evidence_confidence, 0.8)
        final_score = round(min(100.0, max(0.0, score * multiplier)), 1)

        severity = "INFORMATIONAL"
        for thresh, label in cls.SEVERITY_THRESHOLDS:
            if final_score >= thresh:
                severity = label
                break

        return final_score, severity
