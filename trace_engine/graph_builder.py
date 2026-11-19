"""
TRACE Evidence Relationship Graph Builder
Constructs a grounded, factual entity-relationship graph using NetworkX.
Every node and edge represents a verified relationship supported by case telemetry.
"""

from typing import Dict, Any, List, Set, Optional
import networkx as nx
from trace_engine.correlation_models import RelationshipType


class EvidenceGraphBuilder:
    """Builds and queries the NetworkX security relationship graph across CR-26-047."""

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_entity_node(self, node_id: str, label: str, node_type: str, metadata: Optional[Dict[str, Any]] = None):
        """Adds a verified entity node to the graph."""
        attrs = {
            "label": label,
            "node_type": node_type,
            "description": metadata.get("description", "") if metadata else "",
            "evidence_sources": set(metadata.get("evidence_sources", [])) if metadata else set()
        }
        if metadata:
            for k, v in metadata.items():
                if k not in attrs:
                    attrs[k] = v
        self.graph.add_node(node_id, **attrs)

    def add_relationship_edge(
        self,
        source: str,
        target: str,
        relationship_type: str,
        evidence_source: str,
        label: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Adds a typed, evidence-backed edge between two entities."""
        edge_attrs = {
            "relationship_type": relationship_type,
            "evidence_source": evidence_source,
            "label": label
        }
        if metadata:
            edge_attrs.update(metadata)
        self.graph.add_edge(source, target, **edge_attrs)

        # Update evidence sources on both nodes
        if source in self.graph.nodes:
            self.graph.nodes[source].setdefault("evidence_sources", set()).add(evidence_source)
        if target in self.graph.nodes:
            self.graph.nodes[target].setdefault("evidence_sources", set()).add(evidence_source)

    def build_full_case_graph(self, context: Dict[str, Any], cases: List[Any]) -> nx.DiGraph:
        """
        Constructs the comprehensive graph across all verified entities and evidence sources.
        """
        self.graph.clear()

        # 1. System Nodes
        systems = [
            ("sys:LedgerOne", "LedgerOne (Finance)", "System", ["E01", "E18", "E19"]),
            ("sys:HelpDeskr", "HelpDeskr (Support)", "System", ["E02", "E06"]),
            ("sys:SSO", "SSO (Authentication)", "System", ["E03"]),
            ("sys:BlueVault", "BlueVault (Storage)", "System", ["E05"]),
            ("sys:PrivateLink", "PrivateLink Tunnel", "System", ["E15"])
        ]
        for nid, lbl, ntype, evs in systems:
            self.add_entity_node(nid, lbl, ntype, {"evidence_sources": evs, "description": f"Enterprise system {lbl}"})

        # 2. Evidence Document Nodes
        for eid in [f"E{i:02d}" for i in range(1, 21)]:
            self.add_entity_node(f"doc:{eid}", f"Evidence {eid}", "Evidence", {"evidence_sources": [eid]})

        # 3. Key Entities & Credentials
        # TallyBridge Integration & Credential
        self.add_entity_node("vendor:TallyBridge", "TallyBridge Software", "Vendor", {"evidence_sources": ["E04", "E07", "E08", "E12", "E16"]})
        self.add_entity_node("cred:key-tb-07", "key-tb-07 (TallyBridge API Key)", "Credential", {"evidence_sources": ["E04", "E18", "E19"]})
        self.add_entity_node("cred:tb-sync-svc", "tb-sync-svc (HelpDeskr Sync User)", "Credential", {"evidence_sources": ["E02", "E04"]})
        self.add_entity_node("cred:bvk-7f3a", "bvk-7f3a (BlueVault Storage Key)", "Credential", {"evidence_sources": ["E05", "E13"]})

        # Hosts & Networks
        self.add_entity_node("host:10.20.4.77", "10.20.4.77 (tb-build-02)", "Host", {"evidence_sources": ["E15", "E18", "E19", "E20"]})
        self.add_entity_node("net:10.20.4.0/24", "10.20.4.0/24 (Private-Link Subnet)", "Network", {"evidence_sources": ["E15"]})
        self.add_entity_node("net:172.16.8.0/24", "172.16.8.0/24 (Internal Kiosk Subnet)", "Network", {"evidence_sources": ["E03", "E14"]})

        # Vendors & Targets
        self.add_entity_node("vendor:V-0412", "Coastal Packaging Ltd (V-0412)", "Vendor", {"evidence_sources": ["E18", "E19"]})
        self.add_entity_node("account:bank-9083", "Diverted Bank Account (****9083)", "FinancialAccount", {"evidence_sources": ["E19"]})

        # Employees
        self.add_entity_node("user:r.menon", "Rohan Menon (Former AP Clerk)", "Employee", {"evidence_sources": ["E03", "E14", "E09", "E11"]})
        self.add_entity_node("user:s.iyer", "Sunita Iyer (Support Lead)", "Employee", {"evidence_sources": ["E02", "E13"]})
        self.add_entity_node("user:m.sundar", "Madhavi Sundar (Finance Manager)", "Employee", {"evidence_sources": ["E06", "E07", "E19"]})

        # 4. Factual Grounded Edges
        # Integration Relationships (E04)
        self.add_relationship_edge("vendor:TallyBridge", "cred:key-tb-07", RelationshipType.CONTEXTUAL.value, "E04", "issued_credential")
        self.add_relationship_edge("cred:key-tb-07", "sys:LedgerOne", RelationshipType.CONTEXTUAL.value, "E04", "configured_scope_read_write")
        self.add_relationship_edge("vendor:TallyBridge", "cred:tb-sync-svc", RelationshipType.CONTEXTUAL.value, "E04", "integration_user")
        self.add_relationship_edge("cred:tb-sync-svc", "sys:HelpDeskr", RelationshipType.CONTEXTUAL.value, "E04", "admin_integration")

        # Network Relationships (E15)
        self.add_relationship_edge("host:10.20.4.77", "net:10.20.4.0/24", RelationshipType.DIRECT_MATCH.value, "E15", "allocated_ip")
        self.add_relationship_edge("net:10.20.4.0/24", "sys:PrivateLink", RelationshipType.CONTEXTUAL.value, "E15", "routed_through")

        # Financial Attack Relationships (E18, E19)
        self.add_relationship_edge("host:10.20.4.77", "cred:key-tb-07", RelationshipType.DIRECT_MATCH.value, "E18", "invoked_key_from_host")
        self.add_relationship_edge("cred:key-tb-07", "vendor:V-0412", RelationshipType.DIRECT_MATCH.value, "E18", "queried_bank_details")
        self.add_relationship_edge("cred:key-tb-07", "account:bank-9083", RelationshipType.DIRECT_MATCH.value, "E19", "modified_bank_account_chg-8b9888c39b")
        self.add_relationship_edge("vendor:V-0412", "account:bank-9083", RelationshipType.DIRECT_MATCH.value, "E19", "assigned_new_bank_details")

        # Storage & Exfiltration Relationships (E02, E13, E05)
        self.add_relationship_edge("user:s.iyer", "sys:HelpDeskr", RelationshipType.CONTEXTUAL.value, "E02", "routine_tuesday_export")
        self.add_relationship_edge("sys:HelpDeskr", "cred:bvk-7f3a", RelationshipType.DIRECT_MATCH.value, "E13", "leaked_in_ticket_TKT-48213")
        self.add_relationship_edge("cred:bvk-7f3a", "sys:BlueVault", RelationshipType.DIRECT_MATCH.value, "E05", "excess_access_143_customers")

        # Former Employee Relationships (E03, E14)
        self.add_relationship_edge("user:r.menon", "sys:SSO", RelationshipType.DIRECT_MATCH.value, "E03", "authenticated_post_termination_sso-bb8ab61e08")
        self.add_relationship_edge("user:r.menon", "net:172.16.8.0/24", RelationshipType.CONTEXTUAL.value, "E03", "warehouse_kiosk_ip")

        # Evidence Linkage Edges
        evidence_links = [
            ("doc:E04", "cred:key-tb-07"),
            ("doc:E14", "user:r.menon"),
            ("doc:E03", "user:r.menon"),
            ("doc:E18", "host:10.20.4.77"),
            ("doc:E19", "vendor:V-0412"),
            ("doc:E19", "account:bank-9083"),
            ("doc:E15", "host:10.20.4.77"),
            ("doc:E05", "cred:bvk-7f3a"),
            ("doc:E02", "sys:HelpDeskr"),
            ("doc:E06", "sys:HelpDeskr")
        ]
        for src, dst in evidence_links:
            self.add_relationship_edge(src, dst, RelationshipType.CONTEXTUAL.value, src.replace("doc:", ""), "documents_entity")

        return self.graph

    def get_connected_evidence(self, node_id: str) -> List[str]:
        """Returns all evidence IDs connected directly or within 1 hop of the selected node."""
        if node_id not in self.graph:
            return []
        
        evidence_set = set(self.graph.nodes[node_id].get("evidence_sources", []))
        
        # Check neighbors
        for neighbor in self.graph.neighbors(node_id):
            if neighbor.startswith("doc:"):
                evidence_set.add(neighbor.replace("doc:", ""))
            edge_data = self.graph.get_edge_data(node_id, neighbor)
            if edge_data and "evidence_source" in edge_data:
                evidence_set.add(edge_data["evidence_source"])

        # Check predecessors
        for predecessor in self.graph.predecessors(node_id):
            if predecessor.startswith("doc:"):
                evidence_set.add(predecessor.replace("doc:", ""))
            edge_data = self.graph.get_edge_data(predecessor, node_id)
            if edge_data and "evidence_source" in edge_data:
                evidence_set.add(edge_data["evidence_source"])

        return sorted(list(evidence_set))

    def get_case_subgraph(self, primary_entities: List[str]) -> nx.DiGraph:
        """Extracts a focused subgraph containing the primary entities and their immediate connections."""
        sub_nodes = set()
        for ent in primary_entities:
            # Match entity ID directly or partially
            for n in self.graph.nodes:
                if ent.lower() in n.lower() or ent.lower() in str(self.graph.nodes[n].get("label", "")).lower():
                    sub_nodes.add(n)
                    sub_nodes.update(self.graph.neighbors(n))
                    sub_nodes.update(self.graph.predecessors(n))

        if not sub_nodes:
            return nx.DiGraph()

        return self.graph.subgraph(sub_nodes).copy()

    def to_dict_representation(self, graph: Optional[nx.DiGraph] = None) -> Dict[str, Any]:
        """Serializes the NetworkX graph to a dictionary suitable for JSON or Plotly visualization."""
        target_graph = graph if graph is not None else self.graph
        nodes_data = []
        for n, d in target_graph.nodes(data=True):
            node_dict = {
                "id": n,
                "label": d.get("label", n),
                "node_type": d.get("node_type", "Entity"),
                "description": d.get("description", ""),
                "evidence_sources": list(d.get("evidence_sources", []))
            }
            nodes_data.append(node_dict)

        edges_data = []
        for u, v, d in target_graph.edges(data=True):
            edges_data.append({
                "source": u,
                "target": v,
                "label": d.get("label", ""),
                "relationship_type": d.get("relationship_type", "Associated"),
                "evidence_source": d.get("evidence_source", "")
            })

        return {"nodes": nodes_data, "edges": edges_data}
