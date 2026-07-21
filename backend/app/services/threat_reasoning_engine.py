from typing import List, Dict, Any
from app.schemas.threat_reasoning import (
    ThreatReasoning,
    RiskNode,
    DetectionGap,
    RankedPriority,
)


class ThreatReasoningEngine:
    def __init__(self):
        self.TACTIC_WEIGHTS = {
            "Initial Access": 10,
            "Execution": 10,
            "Persistence": 15,
            "Privilege Escalation": 15,
            "Defense Evasion": 20,
            "Credential Access": 25,
            "Discovery": 10,
            "Lateral Movement": 20,
            "Collection": 10,
            "Command and Control": 15,
            "Exfiltration": 20,
            "Impact": 25,
        }

        self.TACTIC_MAP = {
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0011": "Command and Control",
            "TA0010": "Exfiltration",
            "TA0040": "Impact",
        }

        # 1. Dictionary Nama Teknik (Ditambahkan T1204.002)
        self.TECHNIQUE_MAP = {
            "T1566.001": "Spearphishing Attachment",
            "T1003.001": "LSASS Memory / Credential Dumping",
            "T1059.001": "PowerShell Execution",
            "T1021.002": "SMB/Windows Admin Shares",
            "T1486": "Data Encrypted for Impact",
            "T1562.001": "Disable or Modify Tools",
            "T1087.002": "Account Discovery: Domain Account",
            "T1204": "Malicious File",
            "T1071.001": "Web Protocols (C2)",
            "T1204.002": "Malicious File",
        }

        # 2. Pemisahan Controls (Ditambahkan T1204.002)
        self.MITRE_CONTROLS = {
            "T1566.001": [
                "Email Gateway Filtering",
                "User Security Awareness",
                "Disable Office Macros",
            ],
            "T1003.001": [
                "Enable LSASS Protection (RunAsPPL)",
                "Restrict Debug Privileges",
            ],
            "T1059.001": [
                "Enable AMSI",
                "Restrict PowerShell to Constrained Language Mode",
            ],
            "T1021.002": ["Network Segmentation", "Restrict SMB Access via Firewall"],
            "T1486": ["Immutable Backup Solution", "Endpoint Behavior Prevention"],
            "T1562.001": [
                "Tamper Protection for EDR/AV",
                "Restrict Local Admin Rights",
            ],
            "T1204": [
                "Enable Microsoft Defender ASR Rules",
                "Block Internet Macros",
                "Application Control (WDAC/AppLocker)",
            ],
            "T1204.002": [
                "Enable Microsoft Defender ASR Rules",
                "Block Internet Macros",
                "Application Control (WDAC/AppLocker)",
            ],
        }

        # 3. Pemisahan Actions (Ditambahkan T1204.002)
        self.MITRE_ACTIONS = {
            "T1566.001": [
                "Deploy YARA/Sigma rule for phishing attachment detection",
                "Analyze Email Headers & Sender Domain",
            ],
            "T1003.001": [
                "Deploy Sigma rule for LSASS memory dumping (Event ID 10)",
                "Monitor suspicious processes accessing lsass.exe",
            ],
            "T1059.001": [
                "Enable Script Block Logging (Event ID 4104)",
                "Alert on base64 encoded PowerShell payloads",
            ],
            "T1021.002": [
                "Monitor SMB Session Creation",
                "Investigate Admin Share Access (Event ID 5140)",
            ],
            "T1204": [
                "Monitor Office child process creation",
                "Alert on Office spawning PowerShell",
                "Detect Office launching cmd.exe",
                "Enable Office macro logging",
            ],
            "T1486": [
                "Monitor mass file extension changes",
                "Detect Shadow Copy deletion (vssadmin)",
            ],
            "T1562.001": [
                "Alert on Windows Defender service stop commands",
                "Monitor registry changes to security products",
            ],
            "T1204.002": [
                "Monitor Office child process creation",
                "Alert on Office spawning PowerShell",
                "Detect Office launching cmd.exe",
                "Enable Office macro logging",
            ],
        }

    def generate_reasoning(self, cir: Any, graph_analysis: Any) -> ThreatReasoning:
        present_tactics = set()
        present_techniques = set()
        nodes_data = []

        cir_nodes = []
        if isinstance(cir, dict):
            if (
                "attack_graph" in cir
                and isinstance(cir["attack_graph"], dict)
                and "nodes" in cir["attack_graph"]
            ):
                cir_nodes = cir["attack_graph"]["nodes"]
            elif "nodes" in cir:
                cir_nodes = cir["nodes"]
        else:
            attack_graph = getattr(cir, "attack_graph", None)
            if attack_graph and hasattr(attack_graph, "nodes"):
                cir_nodes = getattr(attack_graph, "nodes", [])
            else:
                cir_nodes = getattr(cir, "nodes", [])

        for node in cir_nodes:
            if isinstance(node, dict):
                node_id = node.get("step_id") or node.get("id", "")
                raw_tactic = node.get("tactic", "")
                tech_id = node.get("technique") or node.get("technique_id", "")
            else:
                node_id = getattr(node, "step_id", getattr(node, "id", ""))
                raw_tactic = getattr(node, "tactic", "")
                tech_id = getattr(node, "technique", getattr(node, "technique_id", ""))

            tactic = self.TACTIC_MAP.get(
                raw_tactic.upper(), raw_tactic.title() if raw_tactic else ""
            )

            if tactic and tech_id:
                present_tactics.add(tactic)
                present_techniques.add(tech_id)
                nodes_data.append(
                    {"node_id": node_id, "technique_id": tech_id, "tactic": tactic}
                )

        if not present_tactics:
            return ThreatReasoning(
                severity="Low",
                severity_score=0,
                confidence="Low (No Data)",
                attack_objective="Unknown Objective",
                attack_complexity="Unknown",
                kill_chain_completion="0.0%",
                highest_risk_nodes=[],
                priority_ranking=[],
                detection_gaps=[],
                recommended_actions=[],
                recommended_controls=[],
                executive_summary="Tidak ada node serangan yang dapat dianalisis dari data CIR.",
            )

        # Hitung Severity Score
        severity_score = sum(
            [self.TACTIC_WEIGHTS.get(tactic, 0) for tactic in present_tactics]
        )
        if severity_score <= 30:
            severity = "Low"
        elif severity_score <= 60:
            severity = "Medium"
        elif severity_score <= 90:
            severity = "High"
        else:
            severity = "Critical"

        # 4. Peningkatan Logika Attack Objective
        attack_objective = "Unknown Objective"
        tactic_names = [t.lower() for t in present_tactics]
        tech_ids = [t.lower() for t in present_techniques]

        if "impact" in tactic_names and (
            "data encrypted for impact" in tech_ids or "t1486" in tech_ids
        ):
            attack_objective = "Ransomware"
        elif "credential access" in tactic_names and "lateral movement" in tactic_names:
            attack_objective = "Credential Theft"
        elif "exfiltration" in tactic_names:
            attack_objective = "Data Theft"
        elif "discovery" in tactic_names and "persistence" in tactic_names:
            attack_objective = "Internal Reconnaissance"
        elif "initial access" in tactic_names:
            if "execution" in tactic_names:
                attack_objective = "Phishing-based Malware Delivery"
            else:
                attack_objective = "Initial Compromise"

        # Kill Chain Completion
        total_killchain_stages = 14
        kill_chain_completion = (
            f"{round((len(present_tactics) / total_killchain_stages) * 100, 1)}%"
        )

        # Priority Ranking & Highest Risk Nodes
        highest_risk_nodes = []
        priority_map = {}

        for node in nodes_data:
            tech = node["technique_id"]
            tac = node["tactic"]
            tech_name = self.TECHNIQUE_MAP.get(tech, "Unknown Technique")

            if tac in ["Impact", "Credential Access"]:
                risk_level = "Critical"
            elif tac in ["Lateral Movement", "Defense Evasion", "Privilege Escalation"]:
                risk_level = "High"
            elif tac in [
                "Discovery",
                "Collection",
                "Execution",
                "Initial Access",
                "Command and Control",
            ]:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            highest_risk_nodes.append(
                RiskNode(
                    node_id=node["node_id"],
                    technique_id=tech,
                    tactic=tac,
                    risk_level=risk_level,
                )
            )

            if tech not in priority_map:
                priority_map[tech] = RankedPriority(
                    technique_id=tech, technique_name=tech_name, risk_level=risk_level
                )

        risk_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        sorted_priorities = sorted(
            list(priority_map.values()),
            key=lambda x: risk_weights.get(x.risk_level, 0),
            reverse=True,
        )

        # Detection Gap Engine
        detection_gaps = []
        coverage_data = (
            graph_analysis.get("coverage", {})
            if isinstance(graph_analysis, dict)
            else getattr(graph_analysis, "coverage", {})
        )
        for tech_id in present_techniques:
            status = coverage_data.get(tech_id, "Not Covered")
            tech_name = self.TECHNIQUE_MAP.get(tech_id, "Unknown Technique")
            detection_gaps.append(
                DetectionGap(
                    technique_id=tech_id, technique_name=tech_name, status=status
                )
            )

        # Recommended Actions & Controls
        recommended_actions = []
        recommended_controls = []
        for tech_id in present_techniques:
            if tech_id in self.MITRE_CONTROLS:
                recommended_controls.extend(self.MITRE_CONTROLS[tech_id])
            if tech_id in self.MITRE_ACTIONS:
                recommended_actions.extend(self.MITRE_ACTIONS[tech_id])

            if tech_id not in self.MITRE_CONTROLS and tech_id not in self.MITRE_ACTIONS:
                tech_name = self.TECHNIQUE_MAP.get(tech_id, "Unknown Technique")
                recommended_actions.append(
                    f"Investigate activity related to {tech_name} ({tech_id})"
                )

        recommended_controls = list(set(recommended_controls))
        recommended_actions = list(set(recommended_actions))

        # 5. Peningkatan Gramatikal Executive Summary
        tactics_list = list(present_tactics)
        if len(tactics_list) > 1:
            tactics_str = ", ".join(tactics_list[:-1]) + " dan " + tactics_list[-1]
        elif len(tactics_list) == 1:
            tactics_str = tactics_list[0]
        else:
            tactics_str = ""

        top_priorities = [
            f"{p.technique_name} ({p.technique_id})" for p in sorted_priorities[:3]
        ]
        if len(top_priorities) > 1:
            priorities_str = (
                ", ".join(top_priorities[:-1]) + " dan " + top_priorities[-1]
            )
        elif len(top_priorities) == 1:
            priorities_str = top_priorities[0]
        else:
            priorities_str = "teknik-teknik awal yang terdeteksi"

        executive_summary = (
            f"Serangan ini dikategorikan sebagai {severity} (Score: {severity_score}) "
            f"karena melibatkan tahapan {tactics_str}. "
            f"Jalur serangan menunjukkan {kill_chain_completion} tahapan MITRE ATT&CK telah "
            f"terindikasi sehingga diperlukan prioritas mitigasi pada: {priorities_str}."
        )

        return ThreatReasoning(
            severity=severity,
            severity_score=severity_score,
            confidence="High (Deterministic)",
            attack_objective=attack_objective,
            attack_complexity="Advanced" if severity_score > 60 else "Basic",
            kill_chain_completion=kill_chain_completion,
            highest_risk_nodes=highest_risk_nodes,
            priority_ranking=sorted_priorities,
            detection_gaps=detection_gaps,
            recommended_actions=recommended_actions,
            recommended_controls=recommended_controls,
            executive_summary=executive_summary,
        )
