from collections import defaultdict
from typing import Any

from app.schemas.cti import ConsensusRequest, ConsensusResult, ConsensusTechnique


class ConsensusService:
    def analyze(self, request: ConsensusRequest) -> ConsensusResult:
        if not request.candidates:
            raise ValueError("Consensus requires at least one candidate")

        votes: dict[str, dict[str, float]] = defaultdict(dict)
        for candidate in request.candidates:
            for technique in self._techniques(candidate.cir):
                votes[technique][candidate.model_name] = candidate.confidence

        threshold = max(1, len(request.candidates) // 2 + 1)
        techniques = []
        agreed = []
        disputed = []
        for technique_id, model_votes in sorted(votes.items()):
            confidence = round(sum(model_votes.values()) / len(request.candidates), 3)
            item = ConsensusTechnique(
                technique_id=technique_id,
                consensus_confidence=confidence,
                model_votes=model_votes,
            )
            techniques.append(item)
            if len(model_votes) >= threshold:
                agreed.append(technique_id)
            else:
                disputed.append(technique_id)

        consensus_confidence = (
            round(sum(item.consensus_confidence for item in techniques) / len(techniques), 3)
            if techniques
            else 0.0
        )
        return ConsensusResult(
            model_count=len(request.candidates),
            consensus_confidence=consensus_confidence,
            techniques=techniques,
            agreed_techniques=agreed,
            disputed_techniques=disputed,
        )

    def _techniques(self, payload: dict[str, Any]) -> set[str]:
        graph = payload.get("attack_graph", payload.get("cir", {}).get("attack_graph", payload))
        return {
            str(node.get("technique", "")).upper()
            for node in graph.get("nodes", [])
            if isinstance(node, dict) and node.get("technique")
        }
