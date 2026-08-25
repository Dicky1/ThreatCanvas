import pytest

from app.schemas.collective import Organization, ThreatIntelligencePackage
from app.services.collective_defense import CollectiveDefenseEngine


def package(package_id, confidence, techniques, indicator):
    return ThreatIntelligencePackage(
        package_id=package_id,
        organization=Organization(organization_id=f"org-{package_id}", name="Org"),
        tlp="TLP:GREEN",
        source_confidence=confidence,
        observed_techniques=techniques,
        sanitized_indicators=[indicator],
        provenance=f"source-{package_id}",
    )


def test_collective_correlation_preserves_highest_confidence_and_provenance():
    result = CollectiveDefenseEngine().analyze(
        [
            package("p-low", 0.4, ["T1059.001", "T1486"], {"value": "evil.example"}),
            package("p-high", 0.9, ["T1059.001"], {"value": "evil.example", "token": "secret"}),
        ],
        local_detected_techniques=["T1059.001"],
    )

    technique = result.shared_techniques[0]
    assert technique.confidence == 0.9
    assert technique.source_packages == ["p-high", "p-low"]
    assert technique.provenance == ["source-p-high", "source-p-low"]
    assert result.coverage.local_coverage == 50.0
    assert result.sanitized_indicators[0]["token"] == "[REDACTED]"


def test_tlp_red_and_duplicate_packages_are_rejected():
    red = package("p-red", 1.0, ["T1486"], {"value": "x"})
    red.tlp = "TLP:RED"
    with pytest.raises(ValueError, match="TLP:RED"):
        CollectiveDefenseEngine().analyze([red])

    duplicate = package("p-1", 0.5, ["T1486"], {"value": "x"})
    with pytest.raises(ValueError, match="Duplicate"):
        CollectiveDefenseEngine().analyze([duplicate, duplicate])