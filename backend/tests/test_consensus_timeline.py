from app.schemas.cir import CIRSpecification
from app.schemas.cti import ConsensusRequest, ConsensusCandidate
from app.services.attack_timeline import AttackTimelineService
from app.services.consensus import ConsensusService


def test_consensus_identifies_agreed_and_disputed_techniques():
    request = ConsensusRequest(
        candidates=[
            ConsensusCandidate(
                model_name="model-a",
                confidence=0.9,
                cir={"attack_graph": {"nodes": [{"technique": "T1059.001"}]}},
            ),
            ConsensusCandidate(
                model_name="model-b",
                confidence=0.7,
                cir={"attack_graph": {"nodes": [{"technique": "T1059.001"}, {"technique": "T1486"}]}},
            ),
        ]
    )

    result = ConsensusService().analyze(request)

    assert result.model_count == 2
    assert result.agreed_techniques == ["T1059.001"]
    assert result.disputed_techniques == ["T1486"]


def test_attack_timeline_orders_cir_nodes():
    cir = CIRSpecification(
        scenario_id="scenario-1",
        attack_graph={
            "nodes": [
                {
                    "step_id": "step1",
                    "tactic": "initial-access",
                    "technique": "T1566.001",
                    "target": "email",
                    "action_type": "Phishing",
                },
                {
                    "step_id": "step2",
                    "tactic": "impact",
                    "technique": "T1486",
                    "target": "files",
                    "action_type": "Encryption",
                },
            ],
            "edges": [{"from": "step1", "to": "step2", "relationship": "LEADS_TO"}],
        },
    )

    timeline = AttackTimelineService().build("scenario-1", cir)

    assert [event.timestamp for event in timeline.events] == ["00:00", "00:07"]
    assert timeline.events[1].technique == "T1486"
