import yaml
import uuid
from datetime import datetime
from app.schemas.cir import CIRSpecification, CIRNode

class SigmaCompiler:
    """
    Kompilator deterministik untuk mengubah CIR Graph menjadi Sigma Rules.
    """
    
    def __init__(self, cir_data: CIRSpecification):
        self.cir_data = cir_data

    def _generate_rule_for_node(self, node: CIRNode, scenario_id: str) -> dict:
        rule = {
            "title": f"Deteksi Otomatis: {node.action_type.replace('_', ' ').title()}",
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": f"Rule digenerate otomatis dari CIR Graph untuk scenario {scenario_id}.",
            "author": "ThreatCanvas AI Engine",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "tags": [
                f"attack.{node.tactic.lower()}",
                f"attack.{node.technique.lower().replace('.', '_')}"
            ],
            "logsource": {
                "category": "process_creation",
                "product": "windows"
            },
            "detection": {
                "condition": "selection"
            },
            "level": "high"
        }

        # Mapping evidence ke kondisi Sigma
        selection = {}
        for evidence in node.evidence:
            if evidence.type == "process":
                if evidence.image:
                    selection["Image|endswith"] = f"\\{evidence.image}"
                if evidence.command_line:
                    selection["CommandLine|contains"] = evidence.command_line
            elif evidence.type == "network":
                rule["logsource"]["category"] = "network_connection"
                if evidence.protocol:
                    selection["Protocol"] = evidence.protocol
                    
        if not selection:
            selection["TargetObject"] = node.target

        rule["detection"]["selection"] = selection
        return rule

    def compile(self) -> str:
        """Mengompilasi seluruh node di CIR Graph menjadi dokumen YAML (Sigma)."""
        rules = [self._generate_rule_for_node(node, self.cir_data.scenario_id) 
                 for node in self.cir_data.attack_graph.nodes]
        
        yaml_docs = [yaml.dump(r, sort_keys=False, allow_unicode=True) for r in rules]
        return "\n---\n".join(yaml_docs)