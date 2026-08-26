from typing import Any

from app.schemas.collective import (
    CollectiveGraphEdge,
    CollectiveGraphNode,
    CollectiveDefenseResult,
    CollectiveThreatGraph,
    CoverageSummary,
    SharedAttackPath,
    EmergingAttackPath,
    SharedTechnique,
    ThreatIntelligencePackage,
)
from app.services.evidence_provenance import EvidenceProvenanceEngine
from app.services.threat_reasoning_engine import ThreatReasoningEngine


class CollectiveDefenseEngine:
    """Correlates sanitized intelligence without downgrading trusted observations."""

    def __init__(self, threat_engine: ThreatReasoningEngine | None = None):
        self.threat_engine = threat_engine or ThreatReasoningEngine()

    def analyze(
        self,
        packages: list[ThreatIntelligencePackage],
        local_detected_techniques: list[str] | None = None,
    ) -> CollectiveDefenseResult:
        self._validate_packages(packages)
        observations: dict[str, dict[str, Any]] = {}
        indicators: dict[str, dict[str, Any]] = {}
        paths: dict[tuple[str, ...], dict[str, Any]] = {}
        collective_detected_ids: set[str] = set()

        for package in packages:
            techniques = [technique.upper() for technique in package.observed_techniques]
            collective_detected_ids.update(
                technique.upper() for technique in package.detected_techniques
            )
            for technique_id in techniques:
                observation = observations.setdefault(
                    technique_id,
                    {"confidence": 0.0, "packages": [], "provenance": [], "observed_at": []},
                )
                observation["confidence"] = max(
                    observation["confidence"], package.source_confidence
                )
                observation["packages"].append(package.package_id)
                if package.provenance:
                    observation["provenance"].append(package.provenance)
                if package.observed_at:
                    observation["observed_at"].append(package.observed_at)

            sanitized = self._sanitize_indicators(package.sanitized_indicators)
            for indicator in sanitized:
                key = self._indicator_key(indicator)
                if key not in indicators:
                    indicators[key] = indicator
                else:
                    indicators[key] = {
                        **indicator,
                        **indicators[key],
                    }

            path = tuple(techniques)
            if path:
                path_data = paths.setdefault(path, {"confidence": 0.0, "packages": []})
                path_data["confidence"] = max(
                    path_data["confidence"], package.source_confidence
                )
                path_data["packages"].append(package.package_id)

        shared = [
            SharedTechnique(
                technique_id=technique_id,
                confidence=data["confidence"],
                source_packages=sorted(set(data["packages"])),
                provenance=sorted(set(data["provenance"])),
                observed_at=sorted(set(data["observed_at"])),
            )
            for technique_id, data in sorted(observations.items())
        ]
        shared_ids = {item.technique_id for item in shared}
        local_ids = {technique.upper() for technique in local_detected_techniques or []}
        observed_ids = shared_ids
        if not collective_detected_ids:
            # Backward-compatible behavior for legacy payloads. Newer packages should
            # send detected_techniques so coverage represents detection union.
            collective_detected_ids = shared_ids
        denominator = len(shared_ids)
        collective_graph = self._build_collective_graph(shared, paths)
        emerging = self._derive_emerging_paths(collective_graph, paths)
        controls = {
            technique: list(self.threat_engine.MITRE_CONTROLS.get(technique, []))
            for technique in sorted(shared_ids)
            if technique in self.threat_engine.MITRE_CONTROLS
        }
        return CollectiveDefenseResult(
            shared_techniques=shared,
            sanitized_indicators=list(indicators.values()),
            shared_attack_paths=[
                SharedAttackPath(
                    techniques=list(path),
                    confidence=data["confidence"],
                    source_packages=sorted(set(data["packages"])),
                )
                for path, data in sorted(paths.items())
            ],
            derived_emerging_paths=emerging,
            collective_graph=collective_graph,
            coverage=CoverageSummary(
                observed_techniques=sorted(observed_ids),
                local_techniques=sorted(local_ids),
                collective_detected_techniques=sorted(collective_detected_ids),
                collective_techniques=sorted(shared_ids),
                local_coverage=round(len(local_ids & shared_ids) / denominator * 100, 2)
                if denominator
                else 0.0,
                collective_coverage=round(
                    len(collective_detected_ids & shared_ids) / denominator * 100, 2
                )
                if denominator
                else 0.0,
                detection_gap_techniques=sorted(shared_ids - collective_detected_ids),
            ),
            recommended_controls=controls,
        )

    @staticmethod
    def _derive_emerging_paths(graph: CollectiveThreatGraph, observed_paths: dict[tuple[str, ...], dict[str, Any]]) -> list[EmergingAttackPath]:
        adjacency: dict[str, list[str]] = {}
        indegree: dict[str, int] = {node.technique_id: 0 for node in graph.nodes}
        for edge in graph.edges:
            adjacency.setdefault(edge.source, []).append(edge.target)
            indegree[edge.target] = indegree.get(edge.target, 0) + 1
        starts = [node for node, degree in indegree.items() if degree == 0]
        observed = set(observed_paths)
        results: list[EmergingAttackPath] = []
        def walk(path: list[str]) -> None:
            current = path[-1]
            targets = adjacency.get(current, [])
            if not targets:
                key = tuple(path)
                if len(path) > 2 and key not in observed:
                    path_edges = set(zip(path, path[1:]))
                    supporting_edges = [
                        edge for edge in graph.edges
                        if (edge.source, edge.target) in path_edges
                    ]
                    packages = sorted({pkg for edge in supporting_edges for pkg in edge.source_packages})
                    confidence = min((edge.confidence for edge in supporting_edges), default=0.0)
                    results.append(EmergingAttackPath(techniques=path, confidence=confidence, source_packages=packages, derived_from=packages))
                return
            for target in targets:
                if target not in path and len(path) < 12:
                    walk(path + [target])
        for start in starts:
            walk([start])
        return results

    @staticmethod
    def _build_collective_graph(
        shared: list[SharedTechnique],
        paths: dict[tuple[str, ...], dict[str, Any]],
    ) -> CollectiveThreatGraph:
        node_lookup = {
            item.technique_id: CollectiveGraphNode(
                technique_id=item.technique_id,
                observed_by_count=len(item.source_packages),
                confidence=item.confidence,
                source_packages=item.source_packages,
                emerging=len(item.source_packages) > 1 and item.confidence >= 0.75,
            )
            for item in shared
        }
        edge_lookup: dict[tuple[str, str], dict[str, Any]] = {}
        for path, data in paths.items():
            packages = set(data["packages"])
            for index in range(len(path) - 1):
                key = (path[index], path[index + 1])
                edge = edge_lookup.setdefault(
                    key,
                    {"confidence": 0.0, "packages": set()},
                )
                edge["confidence"] = max(edge["confidence"], data["confidence"])
                edge["packages"].update(packages)

        edges = [
            CollectiveGraphEdge(
                source=source,
                target=target,
                observed_by_count=len(data["packages"]),
                confidence=data["confidence"],
                source_packages=sorted(data["packages"]),
            )
            for (source, target), data in sorted(edge_lookup.items())
        ]
        return CollectiveThreatGraph(
            nodes=sorted(node_lookup.values(), key=lambda node: node.technique_id),
            edges=edges,
        )

    @staticmethod
    def _validate_packages(packages: list[ThreatIntelligencePackage]) -> None:
        package_ids = [package.package_id for package in packages]
        if len(package_ids) != len(set(package_ids)):
            raise ValueError("Duplicate threat intelligence package IDs are not allowed")
        if any(package.tlp == "TLP:RED" for package in packages):
            raise ValueError("TLP:RED intelligence cannot be added to collective analysis")

    @staticmethod
    def _sanitize_indicators(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
        def sanitize(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    key: "[REDACTED]"
                    if key.lower() in {"password", "token", "secret", "api_key"}
                    else sanitize(item)
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [sanitize(item) for item in value]
            if isinstance(value, str):
                return EvidenceProvenanceEngine._redact(value)
            return value

        return [sanitize(indicator) for indicator in indicators]

    @staticmethod
    def _indicator_key(indicator: dict[str, Any]) -> str:
        return str(indicator.get("id") or indicator.get("value") or sorted(indicator.items()))
