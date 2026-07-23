import logging
from typing import List, Any
from collections import deque
from app.schemas.simulation import (
    SimulationResult,
    SimulationMetrics,
    SimulationComparison,
)
from app.schemas.cir import CIRSpecification
from app.services.graph_analysis_engine import GraphAnalysisEngine
from app.services.threat_reasoning_engine import ThreatReasoningEngine
from app.services.cir_validator import CIRValidator

logger = logging.getLogger(__name__)


class AttackSimulationEngine:
    def __init__(self):
        logger.info("AttackSimulationEngine initialized.")

    def _get_node_id(self, node: Any) -> str:
        """Helper ketat untuk menjamin ID node berupa string (misal: 'step-001')."""
        val = getattr(node, "step_id", None)
        if not val:
            val = getattr(node, "id", None)
        return str(val) if val is not None else ""

    def _get_technique(self, node: Any) -> str:
        """Helper ketat untuk mengambil ID teknik MITRE."""
        val = getattr(node, "technique", None)
        if not val:
            val = getattr(node, "technique_id", None)
        return str(val) if val is not None else ""

    def _extract_metrics(
        self, threat_reasoning: Any, graph_analysis: Any
    ) -> SimulationMetrics:
        """Mengekstrak output engine lama dengan pengamanan nilai None dan debugging ketat."""
        
        # 1. Konversi aman threat_reasoning
        if hasattr(threat_reasoning, "model_dump"):
            t_dict = threat_reasoning.model_dump()
        elif hasattr(threat_reasoning, "dict"):
            t_dict = threat_reasoning.dict()
        else:
            t_dict = threat_reasoning if isinstance(threat_reasoning, dict) else (vars(threat_reasoning) if hasattr(threat_reasoning, "__dict__") else {})

        # 2. Konversi aman graph_analysis (Cegah TypeError jika bernilai None)
        if graph_analysis is None:
            g_dict = {}
        elif hasattr(graph_analysis, "model_dump"):
            g_dict = graph_analysis.model_dump()
        elif hasattr(graph_analysis, "dict"):
            g_dict = graph_analysis.dict()
        else:
            g_dict = graph_analysis if isinstance(graph_analysis, dict) else (vars(graph_analysis) if hasattr(graph_analysis, "__dict__") else {})

        logger.info(f"[DEBUG] Available keys in graph_analysis dict: {list(g_dict.keys())}")

        g_stats = g_dict.get("statistics", {})
        if not isinstance(g_stats, dict):
            g_stats = {}

        node_count = g_stats.get("node_count") if "node_count" in g_stats else g_dict.get("node_count", 0)
        edge_count = g_stats.get("edge_count") if "edge_count" in g_stats else g_dict.get("edge_count", 0)
        graph_density = g_stats.get("graph_density") if "graph_density" in g_stats else g_dict.get("graph_density", 0.0)
        avg_degree = g_stats.get("average_degree") if "average_degree" in g_stats else g_dict.get("average_degree", 0.0)
        conn_components = g_stats.get("connected_components") if "connected_components" in g_stats else g_dict.get("connected_components", 1)
        
        maturity = g_stats.get("maturity_level") if "maturity_level" in g_stats else t_dict.get("attack_maturity", "Unknown")
        
        cp = g_dict.get("critical_path", [])
        br = g_dict.get("blast_radius", 0)
        blast_radius_val = len(br) if isinstance(br, list) else br

        return SimulationMetrics(
            severity=t_dict.get("severity", "Low"),
            risk_score=t_dict.get("severity_score", t_dict.get("risk_score", 0)),
            kill_chain_completion=t_dict.get("kill_chain_completion", "0.0%"),
            complexity=t_dict.get("attack_complexity", t_dict.get("complexity", "Basic")),
            maturity_level=maturity,
            critical_path=cp,
            blast_radius=blast_radius_val,
            node_count=node_count,
            edge_count=edge_count,
            graph_density=graph_density,
            connected_components=conn_components,
            average_degree=avg_degree,
        )

    def run_simulation(
        self, original_cir: CIRSpecification, blocked_techniques: List[str]
    ) -> SimulationResult:
        logger.info(f"Starting simulation. Blocked techniques: {blocked_techniques}")

        # 1. Pipeline Original (Before)
        logger.info("Running baseline pipeline on original CIR...")
        CIRValidator.validate(original_cir)

        orig_graph_engine = GraphAnalysisEngine(cir_specification=original_cir)
        orig_graph_analysis = orig_graph_engine.analyze()
        orig_threat_engine = ThreatReasoningEngine()
        orig_threat_reasoning = orig_threat_engine.generate_reasoning(
            original_cir, orig_graph_analysis
        )
        metrics_before = self._extract_metrics(
            orig_threat_reasoning, orig_graph_analysis
        )

        # 2. Persiapan Data Simulasi (Deep Copy)
        simulated_cir = original_cir.model_copy(deep=True)
        original_nodes = simulated_cir.attack_graph.nodes
        original_edges = simulated_cir.attack_graph.edges

        # 3. Identifikasi Node yang diblokir langsung
        blocked_node_ids = {
            self._get_node_id(node)
            for node in original_nodes
            if self._get_technique(node) in blocked_techniques
        }
        logger.info(f"Directly blocked nodes: {blocked_node_ids}")

        # 4. Reachability Analysis (BFS)
        adj_list = {
            self._get_node_id(node): []
            for node in original_nodes
            if self._get_node_id(node) not in blocked_node_ids
        }
        in_degree = {
            self._get_node_id(node): 0
            for node in original_nodes
            if self._get_node_id(node) not in blocked_node_ids
        }

        for edge in original_edges:
            src = str(getattr(edge, "source", ""))
            tgt = str(getattr(edge, "target", ""))
            if src in adj_list and tgt in adj_list:
                adj_list[src].append(tgt)
                in_degree[tgt] += 1

        entry_points = [node_id for node_id, deg in in_degree.items() if deg == 0]

        reachable_nodes = set()
        queue = deque(entry_points)
        while queue:
            current = queue.popleft()
            if current not in reachable_nodes:
                reachable_nodes.add(current)
                for neighbor in adj_list.get(current, []):
                    queue.append(neighbor)

        # 5. Rekonstruksi Attack Graph Baru
        simulated_cir.attack_graph.nodes = [
            node for node in original_nodes if self._get_node_id(node) in reachable_nodes
        ]
        simulated_cir.attack_graph.edges = [
            edge
            for edge in original_edges
            if str(getattr(edge, "source", "")) in reachable_nodes
            and str(getattr(edge, "target", "")) in reachable_nodes
        ]

        logger.info(
            f"Reachability complete. Nodes retained: {len(simulated_cir.attack_graph.nodes)}/{len(original_nodes)}"
        )

        # 6. Pipeline Simulasi (After)
        logger.info("Running simulation pipeline on new Attack Graph...")
        CIRValidator.validate(simulated_cir)
        
        sim_graph_engine = GraphAnalysisEngine(cir_specification=simulated_cir)
        sim_graph_analysis = sim_graph_engine.analyze()
        sim_threat_engine = ThreatReasoningEngine()
        sim_threat_reasoning = sim_threat_engine.generate_reasoning(
            simulated_cir, sim_graph_analysis
        )
        metrics_after = self._extract_metrics(sim_threat_reasoning, sim_graph_analysis)

        # 7. Kalkulasi APDS & Chain Status
        orig_cp_len = len(metrics_before.critical_path)
        sim_cp_len = len(metrics_after.critical_path)

        if len(reachable_nodes) == 0 or (orig_cp_len > 0 and sim_cp_len == 0):
            apds = 100.0
            chain_status = "BROKEN"
        else:
            chain_status = "STILL VIABLE"
            
            path_disruption = 0.0
            if orig_cp_len > 0:
                path_disruption = 1 - (sim_cp_len / orig_cp_len)
                
            node_disruption = 1 - (len(reachable_nodes) / max(1, len(original_nodes)))
            apds = round(((path_disruption * 0.6) + (node_disruption * 0.4)) * 100, 2)

        # 8. Analisis Transisi untuk Output Summary
        removed_node_list = list(
            set([self._get_node_id(n) for n in original_nodes]) - reachable_nodes
        )
        removed_edges_list = [
            f"{getattr(e, 'source', '')} -> {getattr(e, 'target', '')}"
            for e in original_edges
            if str(getattr(e, "source", "")) not in reachable_nodes
            or str(getattr(e, "target", "")) not in reachable_nodes
        ]
        removed_stages = list(
            set([getattr(n, "tactic", "") for n in original_nodes])
            - set([getattr(n, "tactic", "") for n in simulated_cir.attack_graph.nodes])
        )

        # 9. Format Summary String
        summary_text = (
            f"Simulasi memblokir teknik {', '.join(blocked_techniques) if blocked_techniques else 'None'}. "
            f"Attack Chain status: {chain_status}. "
            f"Tahapan serangan yang berhasil digagalkan: {', '.join(removed_stages) if removed_stages else 'Tidak ada'}. "
            f"Severity bertransisi dari {metrics_before.severity} menjadi {metrics_after.severity} "
            f"dengan Attack Path Disruption Score (APDS) sebesar {apds}%."
        )

        try:
            kc_reduction_val = round(
                float(str(metrics_before.kill_chain_completion).strip("%"))
                - float(str(metrics_after.kill_chain_completion).strip("%")),
                1,
            )
        except:
            kc_reduction_val = 0.0

        comparison = SimulationComparison(
            severity_change=f"{metrics_before.severity} -> {metrics_after.severity}",
            risk_score_reduction=metrics_before.risk_score - metrics_after.risk_score,
            kill_chain_reduction=f"-{kc_reduction_val}%",
            blast_radius_reduction=metrics_before.blast_radius
            - metrics_after.blast_radius,
            complexity_change=f"{metrics_before.complexity} -> {metrics_after.complexity}",
        )

        return SimulationResult(
            blocked_techniques=blocked_techniques,
            removed_nodes=removed_node_list,
            removed_edges=removed_edges_list,
            remaining_nodes=list(reachable_nodes),
            metrics_before=metrics_before,
            metrics_after=metrics_after,
            comparison=comparison,
            risk_reduction=metrics_before.risk_score - metrics_after.risk_score,
            attack_path_disruption_score=max(0.0, min(100.0, apds)),
            optimized_controls=[],  
            simulation_summary=summary_text,
        )