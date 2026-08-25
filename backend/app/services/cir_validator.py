import re
from typing import Dict, Any
from app.schemas.cir import CIRSpecification
from app.services.attack_knowledge import ATTACKKnowledgeService


class CIRValidator:
    @staticmethod
    def validate(
        cir: CIRSpecification,
        attack_knowledge: ATTACKKnowledgeService | None = None,
    ) -> Dict[str, Any]:
        attack_knowledge = attack_knowledge or ATTACKKnowledgeService()
        report = {
            "valid": True,
            "groups": {
                "Schema": {"errors": [], "passed": True},
                "Graph": {"errors": [], "passed": True},
                "MITRE": {"errors": [], "passed": True},
                "Evidence": {"errors": [], "passed": True},
            },
        }

        # 1. Validasi MITRE against the loaded ATT&CK knowledge base.
        for node in cir.attack_graph.nodes:
            if not re.match(r"^T\d{4}(\.\d{3})?$", node.technique):
                report["groups"]["MITRE"]["errors"].append(
                    f"Format technique salah: {node.technique}"
                )
                report["groups"]["MITRE"]["passed"] = False
            mitre_errors = attack_knowledge.validate_node(node.technique, node.tactic)
            for error in mitre_errors:
                report["groups"]["MITRE"]["errors"].append(error)
                report["groups"]["MITRE"]["passed"] = False
            if not re.match(r"^TA\d{4}$", node.tactic):
                report["groups"]["MITRE"]["errors"].append(
                    f"Format tactic salah: {node.tactic}"
                )
                report["groups"]["MITRE"]["passed"] = False

        # 2. Validasi Graph (Integrity)
        step_ids = {n.step_id for n in cir.attack_graph.nodes}
        for edge in cir.attack_graph.edges:
            if edge.source not in step_ids or edge.target not in step_ids:
                report["groups"]["Graph"]["errors"].append(
                    f"Edge menghubungkan node tidak ada: {edge.source}->{edge.target}"
                )
                report["groups"]["Graph"]["passed"] = False

        # 3. Validasi Evidence
        for node in cir.attack_graph.nodes:
            if not node.evidence:
                report["groups"]["Evidence"]["errors"].append(
                    f"Node {node.step_id} tidak punya evidence"
                )
                report["groups"]["Evidence"]["passed"] = False

        # Final Status
        report["valid"] = all(group["passed"] for group in report["groups"].values())
        return report
