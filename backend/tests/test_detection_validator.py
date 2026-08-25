from app.schemas.detection import DetectionEvent
from app.services.detection_validator import DetectionValidationService


def sigma_rule():
        return """title: PowerShell test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
tags:
    - attack.ta0002
"""


def test_generated_rule_requires_validation_and_fixture_metrics_are_deterministic():
    result = DetectionValidationService().validate(
        "sigma", sigma_rule(), technique_id="T1059.001"
    )

    assert result.state == "PRODUCTION_CANDIDATE"
    assert result.metrics.tp == 1
    assert result.metrics.fp == 0
    assert result.metrics.tn == 1
    assert result.metrics.fn == 0


def test_failed_rule_is_not_production_ready():
    result = DetectionValidationService().validate(
        "sigma", "title: broken: [", technique_id="T1059.001"
    )

    assert result.state == "FAILED"
    assert result.errors


def test_multi_document_sigma_artifact_is_validated_as_a_set():
    result = DetectionValidationService().validate(
        "sigma",
        sigma_rule() + "---\n" + sigma_rule(),
        technique_id="T1059.001",
    )

    assert result.state == "PRODUCTION_CANDIDATE"
    assert result.metrics.tp == 1


def test_custom_benign_event_creates_false_positive():
    result = DetectionValidationService().validate(
        "sigma",
        sigma_rule(),
        technique_id="T1059.001",
        events=[
            DetectionEvent(
                event={"Image": "powershell.exe", "CommandLine": "malicious"},
                malicious=True,
            ),
            DetectionEvent(
                event={"Image": "powershell.exe", "CommandLine": "admin script"},
                malicious=False,
            )
        ],
    )

    assert result.metrics.fp == 1
    assert result.state == "TESTED"