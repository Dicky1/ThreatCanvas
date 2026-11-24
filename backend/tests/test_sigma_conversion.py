import xml.etree.ElementTree as ET

import pytest

from app.services.sigma_conversion import SigmaConversionError, convert

RULES = """
title: Suspicious PowerShell
id: 11111111-1111-1111-1111-111111111111
logsource: {category: process_creation, product: windows}
level: high
tags: [attack.execution, attack.t1059.001]
detection:
  selection_img: {Image|endswith: '\\powershell.exe'}
  selection_cli: {CommandLine|contains|all: [IEX, DownloadString]}
  condition: 1 of selection_*
---
title: Run key
logsource: {category: registry_set, product: windows}
tags: [attack.persistence, attack.t1547.001]
detection:
  selection: {TargetObject|contains: '\\CurrentVersion\\\\Run', Details|contains: 'it"s.exe'}
  condition: selection
---
title: With filter
logsource: {category: process_creation, product: windows}
detection:
  selection: {Image|endswith: '\\cmd.exe'}
  filter: {User: SYSTEM}
  condition: selection and not filter
"""


@pytest.mark.parametrize("target,needle", [
    ("splunk", 'Image="*\\\\powershell.exe"'),
    ("kql", 'FolderPath endswith "\\\\powershell.exe"'),
    ("elastic", "process.executable"),
])
def test_pysigma_targets_convert_every_rule(target, needle):
    result = convert(RULES, target)
    assert [rule.error for rule in result.rules] == [None, None, None]
    assert needle in result.rules[0].query
    assert result.rules[0].techniques == ["T1059.001"]


def test_wazuh_rules_are_valid_xml_with_doubled_backslashes():
    result = convert(RULES, "wazuh")
    ok = [rule for rule in result.rules if rule.queries]
    assert len(ok) == 2
    assert "not supported for Wazuh" in result.rules[2].error  # 'and not' cannot map: reported, not dropped
    ids = []
    for rule in ok:
        root = ET.fromstring(rule.query)
        for element in root.iter("rule"):
            ids.append(element.get("id"))
    assert len(ids) == len(set(ids)) == 3  # 2 selections + 1, unique across the conversion
    first = ok[0].query
    # Wazuh keeps JSON-escaped backslashes: '\\powershell.exe' must match two literal backslashes.
    assert "(?i)\\\\\\\\powershell\\.exe$" in first
    assert "<id>T1059.001</id>" in first
    assert "(?=.*IEX)(?=.*DownloadString)" in first
    assert ET.fromstring(ok[1].query).find("rule/field[@name='win.eventdata.details']").text.endswith('it"s\\.exe')


def test_invalid_input_and_target():
    with pytest.raises(SigmaConversionError):
        convert("title: [unclosed", "splunk")
    with pytest.raises(SigmaConversionError):
        convert(RULES, "qradar")
    assert convert("title: x\nlogsource: {category: process_creation}\ndetection: {condition: sel}", "splunk").rules[0].error
