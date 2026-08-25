from app.schemas.cir import CIRSpecification
from app.schemas.cti import AttackTimeline, TimelineEvent


class AttackTimelineService:
    def build(self, scenario_id: str, cir: CIRSpecification) -> AttackTimeline:
        events = []
        for index, node in enumerate(cir.attack_graph.nodes):
            events.append(
                TimelineEvent(
                    timestamp=f"00:{index * 7:02d}",
                    node_id=node.step_id,
                    technique=node.technique,
                    tactic=node.tactic,
                    action_type=node.action_type,
                    target=node.target,
                    status="active",
                )
            )
        return AttackTimeline(scenario_id=scenario_id, events=events)
