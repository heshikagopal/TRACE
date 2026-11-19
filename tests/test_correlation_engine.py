"""
Unit Tests for TRACE Cross-System Correlation Engine & Evidence Graph
Tests exact matches, non-matches, multi-format timestamps, missing IDs,
unreliable clock caveats, unverified relationships, and NetworkX graph connectivity.
"""

import unittest
from datetime import datetime, timezone
import networkx as nx
import pandas as pd

from trace_engine.ingestion import EvidenceIngestor
from trace_engine.normalisation import load_and_normalise_all
from trace_engine.correlation_models import RelationshipType, CorrelatedEvent, InvestigationCase
from trace_engine.correlation_scoring import CaseRiskScorer
from trace_engine.correlation import CrossSystemCorrelationEngine
from trace_engine.graph_builder import EvidenceGraphBuilder


class TestCorrelationEngineComprehensive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ingestor = EvidenceIngestor("data/original")
        cls.df_events = load_and_normalise_all(cls.ingestor)
        cls.correlation_engine = CrossSystemCorrelationEngine(cls.ingestor)
        cls.cases = cls.correlation_engine.build_all_cases(cls.df_events)
        cls.graph_builder = EvidenceGraphBuilder()
        cls.context = {
            "E14": cls.ingestor.load_csv("E14"),
            "E04": cls.ingestor.load_json("E04")
        }
        cls.graph = cls.graph_builder.build_full_case_graph(cls.context, list(cls.cases.values()))

    # -------------------------------------------------------------------------
    # 1. EXACT IDENTIFIER MATCHES
    # -------------------------------------------------------------------------
    def test_01_exact_identifier_matches(self):
        """Verifies exact identifier matches across disparate system logs."""
        case_03 = self.cases["CASE-03"]
        direct_matches = [e for e in case_03.timeline if e.relationship_type == RelationshipType.DIRECT_MATCH.value]
        
        # Verify request_id req-5f61b0de8 is directly matched
        matched_req_ids = [e for e in direct_matches if "req-5f61b0de8" in e.identifiers_matched]
        self.assertGreaterEqual(len(matched_req_ids), 2, "req-5f61b0de8 must link E18 and E19 directly")

        # Verify key-tb-07 is present in matched identifiers
        matched_keys = [e for e in direct_matches if "key-tb-07" in e.identifiers_matched]
        self.assertGreaterEqual(len(matched_keys), 1)

    # -------------------------------------------------------------------------
    # 2. INCORRECT IDENTIFIER MATCHES
    # -------------------------------------------------------------------------
    def test_02_incorrect_identifier_matches(self):
        """Ensures that distinct non-matching identifiers are never conflated as direct matches."""
        case_01 = self.cases["CASE-01"]
        # r.menon must NOT match active employee 'f.dsouza'
        for event in case_01.timeline:
            self.assertNotIn("f.dsouza", event.identifiers_matched)
            self.assertNotIn("req-dummy-9999", event.identifiers_matched)

    # -------------------------------------------------------------------------
    # 3. EVENTS WITH DIFFERENT TIMESTAMP FORMATS
    # -------------------------------------------------------------------------
    def test_03_events_with_different_timestamp_formats(self):
        """Verifies multi-format timeline chronological ordering (UTC, IST local, Epoch)."""
        case_04 = self.cases["CASE-04"]
        self.assertGreater(len(case_04.timeline), 3)

        # Check chronological order of parsed datetime objects
        prev_time = datetime.min.replace(tzinfo=timezone.utc)
        for evt in case_04.timeline:
            if evt.timestamp:
                self.assertGreaterEqual(evt.timestamp, prev_time, "Timeline must be monotonically non-decreasing")
                prev_time = evt.timestamp

    # -------------------------------------------------------------------------
    # 4. MISSING IDENTIFIERS HANDLING
    # -------------------------------------------------------------------------
    def test_04_missing_identifiers_handling(self):
        """Verifies events with missing or null identifiers do not raise unhandled exceptions."""
        synthetic_event = CorrelatedEvent(
            event_id="TEST:NO-ID",
            timestamp=datetime.now(timezone.utc),
            timestamp_orig="",
            normalised_timestamp_str="",
            source_system="TestSystem",
            evidence_id="E00",
            description="Event lacking request_id or IP",
            relationship_type=RelationshipType.CONTEXTUAL.value,
            confidence="Unverified",
            identifiers_matched=[]  # Empty identifiers
        )
        score_eval = CaseRiskScorer.evaluate_case("CASE-TEST", [synthetic_event], [])
        self.assertIsInstance(score_eval["final_score"], float)
        self.assertEqual(score_eval["breakdown"]["direct_identifier_matches"]["points"], 0.0)

    # -------------------------------------------------------------------------
    # 5. UNRELIABLE TIMESTAMPS
    # -------------------------------------------------------------------------
    def test_05_unreliable_timestamps_documented(self):
        """Verifies BlueVault clock drift is explicitly documented in uncertainty notes."""
        case_04 = self.cases["CASE-04"]
        bv_events = [e for e in case_04.timeline if e.evidence_id == "E05"]
        self.assertGreater(len(bv_events), 0, "Case 04 must contain E05 events")
        for e in bv_events:
            self.assertIn("drift", e.uncertainty_notes.lower())
            self.assertIn("unsynchronized", e.uncertainty_notes.lower())

    # -------------------------------------------------------------------------
    # 6. UNVERIFIED RELATIONSHIPS
    # -------------------------------------------------------------------------
    def test_06_unverified_relationships_labeled(self):
        """Verifies external vendor advisories (E12) are labeled as Unverified rather than Confirmed."""
        case_02 = self.cases["CASE-02"]
        unverified_evts = [e for e in case_02.timeline if e.relationship_type == RelationshipType.UNVERIFIED.value]
        self.assertGreater(len(unverified_evts), 0, "Case 02 must contain unverified external advisory")
        self.assertEqual(unverified_evts[0].confidence, "Unverified")

    # -------------------------------------------------------------------------
    # 7. LEGITIMATE UNRELATED ACTIVITY EXCLUSION
    # -------------------------------------------------------------------------
    def test_07_legitimate_unrelated_activity_exclusion(self):
        """Verifies ordinary courier/shipment API calls from E01 do not contaminate financial tampering case."""
        case_03 = self.cases["CASE-03"]
        # Case 3 should only focus on vendor V-0412 and related requests
        for evt in case_03.timeline:
            self.assertNotIn("/v2/shipments", evt.description)

    # -------------------------------------------------------------------------
    # 8. NETWORKX EVIDENCE GRAPH INTEGRITY
    # -------------------------------------------------------------------------
    def test_08_evidence_relationship_graph(self):
        """Verifies NetworkX graph node counts, typed edges, and connected evidence lookup."""
        self.assertGreater(len(self.graph.nodes), 15, "Graph must contain entity, system, and document nodes")
        self.assertGreater(len(self.graph.edges), 15, "Graph must contain verified relationship edges")

        # Test selecting node 'cred:key-tb-07' reveals connected evidence
        connected_ev = self.graph_builder.get_connected_evidence("cred:key-tb-07")
        self.assertIn("E04", connected_ev)
        self.assertIn("E18", connected_ev)
        self.assertIn("E19", connected_ev)

        # Test selecting host 10.20.4.77
        host_ev = self.graph_builder.get_connected_evidence("host:10.20.4.77")
        self.assertIn("E15", host_ev)
        self.assertIn("E18", host_ev)

        # Test dictionary export
        dict_rep = self.graph_builder.to_dict_representation()
        self.assertIn("nodes", dict_rep)
        self.assertIn("edges", dict_rep)


if __name__ == "__main__":
    unittest.main()
