import logging
from typing import List, Any
from app.schemas.simulation import OptimizedControl
from app.services.threat_reasoning_engine import ThreatReasoningEngine
from app.services.d3fend_mapping import D3FENDMappingService

logger = logging.getLogger(__name__)


class DefenseOptimizationEngine:
    def __init__(
        self,
        threat_engine: ThreatReasoningEngine,
        d3fend_service: D3FENDMappingService | None = None,
    ):
        self.threat_engine = threat_engine
        self.controls_map = getattr(self.threat_engine, "MITRE_CONTROLS", {})
        self.tactic_weights = getattr(self.threat_engine, "TACTIC_WEIGHTS", {})
        self.tactic_map = getattr(self.threat_engine, "TACTIC_MAP", {})
        self.d3fend_service = d3fend_service or D3FENDMappingService()

    def generate_optimization(
        self,
        original_nodes: List[Any],
        simulated_nodes: List[Any],
        total_risk_score: int,
        attack_paths: List[List[str]] | None = None,
    ) -> List[OptimizedControl]:

        logger.info(
            "Generating defense optimizations based on missing techniques from simulation..."
        )

        orig_techs = {
            getattr(node, "technique", getattr(node, "technique_id", ""))
            for node in original_nodes
        }
        sim_techs = {
            getattr(node, "technique", getattr(node, "technique_id", ""))
            for node in simulated_nodes
        }
        removed_techniques = orig_techs - sim_techs

        control_impact = {}
        d3fend_results = []

        for node in original_nodes:
            tech_id = getattr(node, "technique", getattr(node, "technique_id", ""))
            raw_tactic = getattr(node, "tactic", "")

            if tech_id in removed_techniques and tech_id in self.controls_map:
                tactic = self.tactic_map.get(
                    raw_tactic.upper(), raw_tactic.title() if raw_tactic else ""
                )
                weight = self.tactic_weights.get(
                    tactic, 10
                )  # Default bobot jika tidak ditemukan

                controls = self.controls_map[tech_id]
                for ctrl in controls:
                    if ctrl not in control_impact:
                        control_impact[ctrl] = {"score": 0, "techniques": set()}

                    if tech_id not in control_impact[ctrl]["techniques"]:
                        control_impact[ctrl]["score"] += weight
                        control_impact[ctrl]["techniques"].add(tech_id)

            if tech_id in removed_techniques:
                affected_nodes = [
                    str(getattr(candidate, "step_id", getattr(candidate, "id", "")))
                    for candidate in original_nodes
                    if getattr(candidate, "technique", getattr(candidate, "technique_id", "")) == tech_id
                ]
                affected_paths = [
                    path for path in (attack_paths or []) if set(path) & set(affected_nodes)
                ]
                for mapping in self.d3fend_service.lookup(tech_id):
                    d3fend_results.append(
                        OptimizedControl(
                            control_name=mapping.defensive_technique,
                            risk_reduction_score=self.tactic_weights.get(
                                self.tactic_map.get(str(raw_tactic).upper(), ""), 10
                            ),
                            risk_reduction_percentage="0%",
                            affected_techniques=[tech_id],
                            defensive_technique=mapping.defensive_technique,
                            rationale=mapping.rationale,
                            affected_attack_nodes=affected_nodes,
                            affected_attack_paths=affected_paths,
                            source=mapping.source,
                            confidence=mapping.confidence,
                        )
                    )

        results = []
        for ctrl_name, data in control_impact.items():
            score = data["score"]
            percentage_val = round((score / max(1, total_risk_score)) * 100, 1)
            percentage_str = f"{percentage_val}%"

            results.append(
                OptimizedControl(
                    control_name=ctrl_name,
                    risk_reduction_score=score,
                    risk_reduction_percentage=percentage_str,
                    affected_techniques=list(data["techniques"]),
                )
            )

        # Fallback jika tidak ada kontrol spesifik yang ter-mapping
        if not results and removed_techniques:
            results.append(
                OptimizedControl(
                    control_name="General Defense-in-Depth & Endpoint Monitoring",
                    risk_reduction_score=int(total_risk_score * 0.5),
                    risk_reduction_percentage="50.0%",
                    affected_techniques=list(removed_techniques),
                )
            )

        results.sort(key=lambda x: x.risk_reduction_score, reverse=True)
        return d3fend_results + results
