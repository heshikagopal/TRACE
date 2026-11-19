"""
TRACE Correlation Engine Data Structures
Defines relationship types, correlated event records, and investigation cases.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class RelationshipType(str, Enum):
    DIRECT_MATCH = "Direct Identifier Match"
    TEMPORAL = "Temporal Correlation"
    CONTEXTUAL = "Contextual Association"
    UNVERIFIED = "Unverified Association"


@dataclass
class CorrelatedEvent:
    """A single event situated in an investigative correlation chain."""
    event_id: str
    timestamp: Optional[datetime]
    timestamp_orig: str
    normalised_timestamp_str: str
    source_system: str
    evidence_id: str
    description: str
    relationship_type: str                   # From RelationshipType
    confidence: str                          # 'Confirmed Fact', 'High Confidence', 'Corroborated Context', 'Unverified'
    identifiers_matched: List[str]           # Specific shared keys, IDs, or IPs
    uncertainty_notes: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.timestamp:
            d["timestamp_iso"] = self.timestamp.isoformat()
        else:
            d["timestamp_iso"] = None
        return d


@dataclass
class InvestigationCase:
    """A cohesive investigative case binding related events, entities, and risk factors."""
    case_id: str
    title: str
    focus: str
    primary_entities: List[str]
    primary_evidence_ids: List[str]
    timeline: List[CorrelatedEvent]
    risk_assessment: Dict[str, Any]
    summary: str
    facts_observed: List[str]
    investigative_hypotheses: List[str]
    recommended_actions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timeline"] = [e.to_dict() for e in self.timeline]
        return d
