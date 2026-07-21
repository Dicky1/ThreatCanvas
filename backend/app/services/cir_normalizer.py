from app.schemas.cir import CIRSpecification


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
    def normalize(cir: CIRSpecification) -> CIRSpecification:
        """
        Normalisasi data CIR secara deterministik sebelum divalidasi.
        """
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

        return cir
