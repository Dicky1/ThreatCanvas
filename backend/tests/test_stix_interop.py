from app.services.stix_interop import STIXInteropError, STIXInteropService


def make_bundle():
    return {
        "type": "bundle",
        "spec_version": "2.1",
        "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": "attack-pattern--11111111-1111-4111-8111-111111111111",
                "name": "PowerShell",
                "description": "PowerShell execution observed",
                "confidence": 80,
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            },
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--22222222-2222-4222-8222-222222222222",
                "name": "Example Malware",
                "confidence": 70,
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
                "is_family": False,
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--33333333-3333-4333-8333-333333333333",
                "relationship_type": "uses",
                "source_ref": "malware--22222222-2222-4222-8222-222222222222",
                "target_ref": "attack-pattern--11111111-1111-4111-8111-111111111111",
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-02T00:00:00Z",
            },
        ],
    }


def test_stix_round_trip_preserves_semantics_and_metadata():
    service = STIXInteropService()
    imported = service.import_bundle(make_bundle(), "scenario-1")
    exported = service.export_bundle(imported)
    reimported = service.import_bundle(exported, "scenario-2")

    assert reimported.attack_graph.nodes[0].technique == "T1059.001"
    assert reimported.attack_graph.nodes[0].tactic == "TA0002"
    assert reimported.entities[0].confidence == 0.8
    assert reimported.entities[0].created_at.isoformat() == "2026-01-01T00:00:00+00:00"
    assert reimported.relationships[0].relationship == "USES"
    assert {entity.stix_id for entity in reimported.entities} == {
        "attack-pattern--11111111-1111-4111-8111-111111111111",
        "malware--22222222-2222-4222-8222-222222222222",
    }


def test_duplicate_and_unsupported_objects_are_rejected():
    service = STIXInteropService()
    bundle = make_bundle()
    bundle["objects"].append(dict(bundle["objects"][0]))
    try:
        service.import_bundle(bundle, "scenario-1")
        assert False, "duplicate objects must be rejected"
    except STIXInteropError as error:
        assert "duplicate" in str(error).lower()

    unsupported = make_bundle()
    unsupported["objects"][0]["type"] = "identity"
    try:
        service.import_bundle(unsupported, "scenario-1")
        assert False, "unsupported objects must be rejected"
    except STIXInteropError as error:
        assert "unsupported" in str(error).lower()