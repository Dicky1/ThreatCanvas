from app.schemas.cir import CIRSpecification
from app.services.attack_knowledge import ATTACKKnowledgeService


class CIRNormalizer:
    TECHNIQUE_MAP = {
        "phishing": "T1566",
        "powershell": "T1059.001",
        "registry modification": "T1112",
        "credential dumping": "T1003",
        "scheduled task": "T1053",
        "network discovery": "T1016",
        "remote services": "T1021",
    }

    TACTIC_MAP = {
        "initial access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege escalation": "TA0004",
        "defense evasion": "TA0005",
        "credential access": "TA0006",
        "discovery": "TA0007",
        "lateral movement": "TA0008",
        "collection": "TA0009",
        "exfiltration": "TA0010",
        "command and control": "TA0011",
    }

    @staticmethod
    def normalize(
        cir: CIRSpecification,
        attack_knowledge: ATTACKKnowledgeService | None = None,
    ) -> CIRSpecification:
        """
        Normalisasi data CIR secara deterministik sebelum divalidasi.
        """
        knowledge = attack_knowledge or ATTACKKnowledgeService()
        if hasattr(cir, "attack_graph") and hasattr(cir.attack_graph, "nodes"):
            for node in cir.attack_graph.nodes:
                # Normalisasi Technique
                tech_val = str(getattr(node, "technique", "")).lower().strip()
                if tech_val in CIRNormalizer.TECHNIQUE_MAP:
                    node.technique = CIRNormalizer.TECHNIQUE_MAP[tech_val]

                # Normalisasi Tactic
                tact_val = str(getattr(node, "tactic", "")).lower().strip()
                if tact_val in CIRNormalizer.TACTIC_MAP:
                    node.tactic = CIRNormalizer.TACTIC_MAP[tact_val]

                # Tactic harus mengikuti katalog ATT&CK untuk teknik yang sudah
                # ter-resolve. Ini mencegah output LLM yang memasangkan tactic
                # valid tetapi tidak sesuai dengan tekniknya (mis. T1486/TA0059).
                if knowledge is not None:
                    technique = knowledge.resolve_technique(str(node.technique))
                    if technique and technique.tactics and node.tactic not in technique.tactics:
                        node.tactic = technique.tactics[0]

        return knowledge.resolve_cir(cir)
