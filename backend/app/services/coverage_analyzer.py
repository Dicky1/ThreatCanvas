from app.schemas.cir import CIRSpecification

ALL_TACTICS = {
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
}


class CoverageAnalyzer:
    def __init__(self, cir: CIRSpecification):
        self.cir = cir

    def analyze(self):
        nodes = self.cir.attack_graph.nodes
        edges = self.cir.attack_graph.edges

        covered_tactics = {node.tactic for node in nodes if node.tactic}

        covered_techniques = {node.technique for node in nodes if node.technique}

        threat_completeness = (len(covered_tactics) / len(ALL_TACTICS)) * 100

        graph_integrity = len(edges) / len(nodes) if nodes else 0

        return {
            "overall_score": round(
                (threat_completeness + graph_integrity * 10) / 2,
                2,
            ),
            "threat_completeness": round(
                threat_completeness,
                2,
            ),
            "graph_integrity": round(
                graph_integrity,
                2,
            ),
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "covered_tactics": sorted(covered_tactics),
            "covered_techniques": sorted(covered_techniques),
            "missing_tactics": sorted(ALL_TACTICS - covered_tactics),
            "recommendations": self._generate_recommendations(covered_tactics),
        }

    def _generate_recommendations(
        self,
        covered_tactics,
    ):
        recommendations = []

        for tactic in sorted(ALL_TACTICS - covered_tactics):
            recommendations.append(
                f"Pertimbangkan menambahkan aktivitas pada tactic '{tactic}'."
            )

        return recommendations
