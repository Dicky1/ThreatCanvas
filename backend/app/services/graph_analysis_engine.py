import json
from typing import List, Dict, Set
from collections import defaultdict, deque
from app.schemas.graph_analysis import AttackGraphAnalysis, HighRiskNode, BlastRadius


class GraphAnalysisEngine:
    def __init__(self, cir_specification):
        # 1. Pastikan format JSON terbaca sebagai Dictionary
        if isinstance(cir_specification, str):
            try:
                self.cir = json.loads(cir_specification)
            except Exception:
                self.cir = {}
        else:
            self.cir = cir_specification or {}

        # 2. Gunakan smart extractor
        self.nodes = self._extract_data("nodes")
        self.edges = self._extract_data("edges")

        self.adj_list = defaultdict(list)
        self.rev_adj_list = defaultdict(list)

        self.in_degree = defaultdict(int)
        self.out_degree = defaultdict(int)

        self._build_graph()

    def _extract_data(self, target_key: str) -> List[dict]:
        """
        Fungsi rekursif pintar untuk mencari key 'nodes' atau 'edges'
        meskipun tersembunyi jauh di dalam nested JSON object.
        """

        def search_nested(data):
            if isinstance(data, dict):
                if target_key in data and isinstance(data[target_key], list):
                    return data[target_key]
                for v in data.values():
                    result = search_nested(v)
                    if result is not None:
                        return result
            elif isinstance(data, list):
                for item in data:
                    result = search_nested(item)
                    if result is not None:
                        return result
            return None

        found_data = search_nested(self.cir)
        data_list = found_data if isinstance(found_data, list) else []

        # Normalisasi ke bentuk dictionary
        return [
            item if isinstance(item, dict) else item.dict()
            for item in data_list
            if item
        ]

    def _build_graph(self):
        for node in self.nodes:
            # Menggunakan 'step_id' sesuai data CIR
            node_id = node.get("step_id") or node.get("id")
            if node_id:
                self.in_degree[node_id] = 0
                self.out_degree[node_id] = 0

        for edge in self.edges:
            # Menggunakan 'from' dan 'to' sesuai data CIR
            src = edge.get("from") or edge.get("source")
            dst = edge.get("to") or edge.get("target")
            if src and dst:
                self.adj_list[src].append(dst)
                self.rev_adj_list[dst].append(src)
                self.out_degree[src] += 1
                self.in_degree[dst] += 1

    def _find_attack_chains(
        self, entry_points: List[str], exit_points: List[str]
    ) -> List[List[str]]:
        chains = []
        exit_set = set(exit_points)

        def dfs(current_node, path, visited):
            if current_node in exit_set:
                chains.append(list(path))

            for neighbor in self.adj_list[current_node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs(neighbor, path, visited)
                    path.pop()
                    visited.remove(neighbor)

        for entry in entry_points:
            dfs(entry, [entry], {entry})

        return chains

    def _get_connected_components(self) -> int:
        visited = set()
        components = 0

        def bfs(start_node):
            queue = deque([start_node])
            visited.add(start_node)
            while queue:
                curr = queue.popleft()
                neighbors = self.adj_list[curr] + self.rev_adj_list[curr]
                for n in neighbors:
                    if n not in visited:
                        visited.add(n)
                        queue.append(n)

        for node in self.nodes:
            node_id = node.get("step_id") or node.get("id")
            if node_id and node_id not in visited:
                bfs(node_id)
                components += 1

        return components

    def analyze(self) -> AttackGraphAnalysis:
        V = len(self.nodes)
        E = len(self.edges)

        # Mencegah error jika graf masih benar-benar kosong
        if V == 0:
            return None

        # 1 & 2. Entry and Exit Points
        entry_points = [n for n, deg in self.in_degree.items() if deg == 0 and V > 1]
        exit_points = [n for n, deg in self.out_degree.items() if deg == 0 and V > 1]

        # Jika graf hanya memiliki node tunggal tanpa edge, otomatis jadi entry dan exit
        if V == 1 and E == 0:
            single_node = list(self.in_degree.keys())[0]
            entry_points = [single_node]
            exit_points = [single_node]

        # 7. Isolated Nodes
        isolated_nodes = [
            n
            for n in self.in_degree.keys()
            if self.in_degree[n] == 0 and self.out_degree[n] == 0
        ]

        # Jangan hapus entry/exit jika grafnya memang terisolasi semua (misal edges kosong)
        if E > 0:
            entry_points = [n for n in entry_points if n not in isolated_nodes]
            exit_points = [n for n in exit_points if n not in isolated_nodes]

        # 4. Attack Chains & 3. Critical Path
        attack_chains = self._find_attack_chains(entry_points, exit_points)
        critical_path = max(attack_chains, key=len) if attack_chains else []

        # 10 & 11. Longest / Shortest Chain
        chain_lengths = [len(c) for c in attack_chains]
        longest_chain = max(chain_lengths) if chain_lengths else 0
        shortest_chain = min(chain_lengths) if chain_lengths else 0

        # 5. Graph Density (Directed)
        graph_density = E / (V * (V - 1)) if V > 1 else 0.0

        # 6. Connected Components
        connected_components = self._get_connected_components()

        # 8 & 9. Node Degrees
        total_in = sum(self.in_degree.values())
        total_out = sum(self.out_degree.values())
        avg_in_degree = total_in / V if V > 0 else 0.0
        avg_out_degree = total_out / V if V > 0 else 0.0
        avg_degree = (total_in + total_out) / V if V > 0 else 0.0

        # 12. Kill Chain Completion
        mitre_tactics = set()
        for n in self.nodes:
            tactic = n.get("tactic") or n.get("mitre_tactic")
            if tactic:
                mitre_tactics.add(tactic.lower())
        kill_chain_completion = (len(mitre_tactics) / 14.0) * 100

        # 13. Detection Choke Points
        path_counts = defaultdict(int)
        total_paths = len(attack_chains)
        for chain in attack_chains:
            for node in set(chain):
                if node not in entry_points and node not in exit_points:
                    path_counts[node] += 1

        detection_choke_points = [
            node
            for node, count in path_counts.items()
            if total_paths > 0 and (count / total_paths) > 0.5
        ]

        # 14. High Risk Nodes
        high_risk_nodes = []
        high_risk_tactics = [
            "credential access",
            "privilege escalation",
            "defense evasion",
            "lateral movement",
            "impact",
        ]
        for node in self.nodes:
            tactic = (node.get("tactic") or node.get("mitre_tactic") or "").lower()
            if tactic in high_risk_tactics:
                node_id = node.get("step_id") or node.get("id")
                if node_id:
                    high_risk_nodes.append(
                        HighRiskNode(
                            node_id=node_id, score=10, matched_tactics=[tactic]
                        )
                    )

        # 15. Blast Radius (Reachability via BFS)
        blast_radius_list = []
        for node in self.nodes:
            node_id = node.get("step_id") or node.get("id")
            if not node_id:
                continue
            visited = set()
            queue = deque([node_id])
            while queue:
                curr = queue.popleft()
                for neighbor in self.adj_list[curr]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
            blast_radius_list.append(
                BlastRadius(
                    node_id=node_id,
                    impacted_count=len(visited),
                    impacted_nodes=list(visited),
                )
            )

        # 16. Attack Complexity
        avg_chain = sum(chain_lengths) / len(chain_lengths) if chain_lengths else 0
        attack_complexity = round(((V + E) * avg_chain) / 10.0, 2)

        # 17. Attack Maturity
        if kill_chain_completion >= 80 or attack_complexity > 50:
            attack_maturity = "High"
        elif kill_chain_completion >= 40 or attack_complexity > 20:
            attack_maturity = "Medium"
        else:
            attack_maturity = "Low"

        # Calculate coverage percentage
        nodes_in_chains = set()
        for chain in attack_chains:
            nodes_in_chains.update(chain)
        coverage_percentage = (len(nodes_in_chains) / V) * 100 if V > 0 else 0.0

        return AttackGraphAnalysis(
            node_count=V,
            edge_count=E,
            entry_points=entry_points,
            exit_points=exit_points,
            critical_path=critical_path,
            attack_chains=attack_chains,
            graph_density=round(graph_density, 3),
            connected_components=connected_components,
            isolated_nodes=isolated_nodes,
            average_degree=round(avg_degree, 2),
            average_in_degree=round(avg_in_degree, 2),
            average_out_degree=round(avg_out_degree, 2),
            longest_chain=longest_chain,
            shortest_chain=shortest_chain,
            kill_chain_completion=round(kill_chain_completion, 2),
            coverage_percentage=round(coverage_percentage, 2),
            detection_choke_points=detection_choke_points,
            high_risk_nodes=high_risk_nodes,
            blast_radius=blast_radius_list,
            attack_complexity=attack_complexity,
            attack_maturity=attack_maturity,
        )
