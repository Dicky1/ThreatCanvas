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
from app.services.rw_apds import RWAPDSCalculator

logger = logging.getLogger(__name__)


class AttackSimulationEngine:
    def __init__(self):
        logger.info("AttackSimulationEngine initialized.")

    def _get_node_id(self, node: Any) -> str:
        """Konsisten mengambil step_id secara mutlak agar frontend tidak perlu konversi."""
        val = getattr(node, "step_id", None)
        if not val or str(val).strip() == "":
            val = getattr(node, "id", None)
        return str(val) if val is not None else ""

    def _get_technique(self, node: Any) -> str:
        val = getattr(node, "technique", None)
        if not val:
            val = getattr(node, "technique_id", None)
        return str(val) if val is not None else ""

    def _get_tactic(self, node: Any) -> str:
        return str(getattr(node, "tactic", "Unknown"))

    def _extract_metrics(
        self, threat_reasoning: Any, graph_analysis: Any, cir: CIRSpecification = None
    ) -> SimulationMetrics:
        """Mengekstrak metrik dengan membaca langsung atribut objek kelas Python murni maupun dict."""

        if hasattr(threat_reasoning, "model_dump"):
            t_dict = threat_reasoning.model_dump()
        elif hasattr(threat_reasoning, "dict"):
            t_dict = threat_reasoning.dict()
        else:
            t_dict = (
                threat_reasoning
                if isinstance(threat_reasoning, dict)
                else (
                    vars(threat_reasoning)
                    if hasattr(threat_reasoning, "__dict__")
                    else {}
                )
            )

        def get_attr_or_key(obj, name, default):
            if obj is None:
                return default
            if isinstance(obj, dict):
                return obj.get(name, default)
            return getattr(obj, name, default)

        stats_obj = get_attr_or_key(
            graph_analysis,
            "statistics",
            get_attr_or_key(graph_analysis, "stats", graph_analysis),
        )

        nodes_in_cir = (
            len(cir.attack_graph.nodes) if cir and hasattr(cir, "attack_graph") else 0
        )
        edges_in_cir = (
            len(cir.attack_graph.edges) if cir and hasattr(cir, "attack_graph") else 0
        )

        node_count = get_attr_or_key(
            stats_obj,
            "node_count",
            get_attr_or_key(graph_analysis, "node_count", nodes_in_cir),
        )
        if node_count == 0 and nodes_in_cir > 0:
            node_count = nodes_in_cir

        edge_count = get_attr_or_key(
            stats_obj,
            "edge_count",
            get_attr_or_key(graph_analysis, "edge_count", edges_in_cir),
        )
        if edge_count == 0 and edges_in_cir > 0:
            edge_count = edges_in_cir

        calc_density = (
            round(edge_count / (node_count * (node_count - 1)), 4)
            if node_count > 1
            else 0.0
        )
        calc_avg_degree = round(edge_count / node_count, 2) if node_count > 0 else 0.0

        graph_density = get_attr_or_key(
            stats_obj,
            "graph_density",
            get_attr_or_key(graph_analysis, "graph_density", calc_density),
        )
        if graph_density == 0.0 and calc_density > 0.0:
            graph_density = calc_density

        avg_degree = get_attr_or_key(
            stats_obj,
            "average_degree",
            get_attr_or_key(graph_analysis, "average_degree", calc_avg_degree),
        )
        if avg_degree == 0.0 and calc_avg_degree > 0.0:
            avg_degree = calc_avg_degree

        conn_components = get_attr_or_key(
            stats_obj,
            "connected_components",
            get_attr_or_key(graph_analysis, "connected_components", 1),
        )
        maturity = get_attr_or_key(
            stats_obj,
            "maturity_level",
            get_attr_or_key(
                graph_analysis,
                "maturity_level",
                t_dict.get("attack_maturity", "Advanced"),
            ),
        )

        cp = get_attr_or_key(
            graph_analysis,
            "critical_path",
            get_attr_or_key(stats_obj, "critical_path", []),
        )
        if not isinstance(cp, list):
            cp = []
        if not cp and cir and hasattr(cir, "attack_graph") and cir.attack_graph.nodes:
            cp = [self._get_node_id(n) for n in cir.attack_graph.nodes]

        br = get_attr_or_key(
            graph_analysis,
            "blast_radius",
            get_attr_or_key(stats_obj, "blast_radius", 0),
        )
        blast_radius_val = (
            len(br) if isinstance(br, list) else (br if br else node_count)
        )

        return SimulationMetrics(
            severity=t_dict.get("severity", "Medium"),
            risk_score=t_dict.get("severity_score", t_dict.get("risk_score", 60)),
            kill_chain_completion=t_dict.get("kill_chain_completion", "35.7%"),
            complexity=t_dict.get(
                "attack_complexity", t_dict.get("complexity", "Basic")
            ),
            maturity_level=str(maturity),
            critical_path=cp,
            blast_radius=blast_radius_val,
            node_count=int(node_count),
            edge_count=int(edge_count),
            graph_density=float(graph_density),
            connected_components=int(conn_components),
            average_degree=float(avg_degree),
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
            orig_threat_reasoning, orig_graph_analysis, original_cir
        )

        # 2. Persiapan Data Simulasi (Deep Copy)
        simulated_cir = original_cir.model_copy(deep=True)
        original_nodes = simulated_cir.attack_graph.nodes
        original_edges = simulated_cir.attack_graph.edges

        all_existing_techniques = {self._get_technique(n) for n in original_nodes}
        matching_blocked = [
            tech for tech in blocked_techniques if tech in all_existing_techniques
        ]

        # 3. Identifikasi Node yang diblokir langsung
        blocked_node_ids = {
            self._get_node_id(node)
            for node in original_nodes
            if self._get_technique(node) in blocked_techniques
        }
        logger.info(f"Directly blocked nodes: {blocked_node_ids}")

        node_map = {self._get_node_id(n): n for n in original_nodes}

        # 4. Reachability Analysis (BFS dengan Cascading Cut-off)
        adj_list = {self._get_node_id(node): [] for node in original_nodes}
        for edge in original_edges:
            src = str(getattr(edge, "source", getattr(edge, "from", "")))
            tgt = str(getattr(edge, "target", getattr(edge, "to", "")))
            if src in adj_list:
                adj_list[src].append(tgt)

        in_degree = {self._get_node_id(node): 0 for node in original_nodes}
        for edge in original_edges:
            tgt = str(getattr(edge, "target", getattr(edge, "to", "")))
            if tgt in in_degree:
                in_degree[tgt] += 1

        original_entry_points = [
            node_id for node_id, deg in in_degree.items() if deg == 0
        ]

        reachable_nodes = set()
        queue = deque(original_entry_points)

        while queue:
            current = queue.popleft()
            if current in blocked_node_ids:
                continue

            if current not in reachable_nodes:
                reachable_nodes.add(current)
                for neighbor in adj_list.get(current, []):
                    if (
                        neighbor not in reachable_nodes
                        and neighbor not in blocked_node_ids
                    ):
                        queue.append(neighbor)

        # 5. Rekonstruksi Attack Graph Baru
        simulated_cir.attack_graph.nodes = [
            node
            for node in original_nodes
            if self._get_node_id(node) in reachable_nodes
        ]
        simulated_cir.attack_graph.edges = [
            edge
            for edge in original_edges
            if str(getattr(edge, "source", getattr(edge, "from", "")))
            in reachable_nodes
            and str(getattr(edge, "target", getattr(edge, "to", ""))) in reachable_nodes
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
        metrics_after = self._extract_metrics(
            sim_threat_reasoning, sim_graph_analysis, simulated_cir
        )

        rw_apds = RWAPDSCalculator().score(
            baseline_nodes=list(original_nodes),
            residual_nodes=list(simulated_cir.attack_graph.nodes),
            baseline_paths=self._get_paths(orig_graph_analysis),
            residual_paths=self._get_paths(sim_graph_analysis),
            critical_paths=[metrics_before.critical_path],
        )

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

        # 8. Analisis Transisi Terstruktur (Removed Nodes & Edges)
        unreachable_nodes = (
            set([self._get_node_id(n) for n in original_nodes]) - reachable_nodes
        )

        removed_nodes_structured = []
        for n_id in sorted(list(unreachable_nodes)):
            node_obj = node_map.get(n_id)
            reason = (
                "Blocked Technique"
                if n_id in blocked_node_ids
                else "Cascading Unreachable (Disconnected)"
            )
            removed_nodes_structured.append(
                {
                    "step_id": n_id,
                    "technique": (
                        self._get_technique(node_obj) if node_obj else "Unknown"
                    ),
                    "tactic": self._get_tactic(node_obj) if node_obj else "Unknown",
                    "reason": reason,
                }
            )

        removed_edges_structured = []
        for edge in original_edges:
            src = str(getattr(edge, "source", getattr(edge, "from", "")))
            tgt = str(getattr(edge, "target", getattr(edge, "to", "")))
            if src not in reachable_nodes or tgt not in reachable_nodes:
                removed_edges_structured.append(
                    {
                        "from": src,
                        "to": tgt,
                        "relationship": getattr(edge, "relationship", "leads_to"),
                    }
                )

        sorted_remaining_nodes = sorted(list(reachable_nodes))

        # 9. Format Summary String
        summary_text = (
            f"Blocked Techniques: {', '.join(blocked_techniques) if blocked_techniques else 'None'}. | "
            f"Removed Nodes Count: {len(removed_nodes_structured)}. | "
            f"Critical Path Reduction: {orig_cp_len} -> {sim_cp_len} nodes. | "
            f"Attack Chain Status: {chain_status}. | "
            f"Severity: {metrics_before.severity} -> {metrics_after.severity} (APDS: {apds}%)."
        )

        try:
            kc_reduction_val = round(
                float(str(metrics_before.kill_chain_completion).strip("%"))
                - float(str(metrics_after.kill_chain_completion).strip("%")),
                1,
            )
        except:
            kc_reduction_val = 0.0

        # 10. Enhanced Comparison (Poin 3: Ditambahkan node_reduction, edge_reduction, critical_path_reduction)
        node_reduction_count = metrics_before.node_count - metrics_after.node_count
        edge_reduction_count = metrics_before.edge_count - metrics_after.edge_count
        cp_reduction_count = orig_cp_len - sim_cp_len
        density_change_val = round(
            metrics_after.graph_density - metrics_before.graph_density, 4
        )

        comparison = SimulationComparison(
            severity_change=f"{metrics_before.severity} -> {metrics_after.severity}",
            risk_score_reduction=metrics_before.risk_score - metrics_after.risk_score,
            kill_chain_reduction=f"-{kc_reduction_val}%",
            blast_radius_reduction=metrics_before.blast_radius
            - metrics_after.blast_radius,
            complexity_change=f"{metrics_before.complexity} -> {metrics_after.complexity}",
            node_reduction=node_reduction_count,
            edge_reduction=edge_reduction_count,
            apds_change=f"{apds}%",
            critical_path_reduction=cp_reduction_count,
            graph_density_change=density_change_val,
        )

        # 11. Penanganan Warning (Poin 2: Info informatif jika teknik tidak ada di graph)
        warning_msg = None
        if not matching_blocked and blocked_techniques:
            warning_msg = (
                "None of the blocked techniques were found in the attack graph."
            )
            logger.warning(warning_msg)

        result = SimulationResult(
            blocked_techniques=blocked_techniques,
            removed_nodes=removed_nodes_structured,
            removed_edges=removed_edges_structured,
            remaining_nodes=sorted_remaining_nodes,
            metrics_before=metrics_before,
            metrics_after=metrics_after,
            comparison=comparison,
            risk_reduction=metrics_before.risk_score - metrics_after.risk_score,
            attack_path_disruption_score=max(0.0, min(100.0, apds)),
            optimized_controls=[],
            simulation_summary=summary_text,
            rw_apds=rw_apds,
        )

        if warning_msg and hasattr(result, "warning"):
            setattr(result, "warning", warning_msg)

        return result

    @staticmethod
    def _get_paths(analysis: Any) -> list[list[str]]:
        if analysis is None:
            return []
        paths = getattr(analysis, "attack_chains", [])
        return [list(path) for path in paths if isinstance(path, list)]
