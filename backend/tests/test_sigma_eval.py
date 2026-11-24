import pytest

from app.services.sigma_eval import SigmaEvalError, compile_rules, prepare_event, rule_matches

PROC = {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"}


def rule(detection: str, category: str = "process_creation", tags: str = "[]"):
    rules, errors = compile_rules(
        f"title: t\nlogsource: {{category: {category}, product: windows}}\ntags: {tags}\ndetection:\n{detection}"
    )
    assert not errors, errors
    return rules[0]


def hit(r, **fields):
    return rule_matches(r, prepare_event({**PROC, **fields}))


def test_modifiers_and_case_insensitivity():
    r = rule("  s:\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains|all: [IEX, DownloadString]\n  condition: s")
    assert hit(r, Image="C:\\Windows\\POWERSHELL.EXE", CommandLine="iex (New-Object Net.WebClient).downloadstring('x')")
    assert not hit(r, Image="C:\\Windows\\powershell.exe", CommandLine="IEX only")


def test_sigma_backslash_escaping_matches_one_backslash():
    single = rule("  s: {Image|endswith: '\\cmd.exe'}\n  condition: s")
    escaped = rule("  s: {Image|endswith: '\\\\cmd.exe'}\n  condition: s")  # Sigma "\\\\" == one backslash
    for r in (single, escaped):
        assert hit(r, Image="C:\\Windows\\cmd.exe")
        assert not hit(r, Image="C:\\Windows\\notcmd.exe")


def test_list_values_are_ored_and_wildcards_work():
    r = rule("  s:\n    Image: ['*\\\\cmd.exe', 'C:\\\\Tools\\\\nc?.exe']\n  condition: s")
    assert hit(r, Image="C:\\Windows\\System32\\cmd.exe")
    assert hit(r, Image="C:\\Tools\\nc6.exe")
    assert not hit(r, Image="C:\\Tools\\nc64.exe")


def test_condition_grammar():
    r = rule(
        "  sel_a: {Image|endswith: a.exe}\n  sel_b: {Image|endswith: b.exe}\n"
        "  filter: {User: SYSTEM}\n  condition: (1 of sel_*) and not filter"
    )
    assert hit(r, Image="x\\a.exe", User="alice")
    assert not hit(r, Image="x\\a.exe", User="system")
    assert not hit(r, Image="x\\c.exe", User="alice")
    every = rule("  sel_a: {Image|contains: a}\n  sel_b: {Image|contains: b}\n  condition: all of sel_*")
    assert hit(every, Image="ab") and not hit(every, Image="a")


def test_list_of_maps_keywords_null_cidr_windash_exists():
    r = rule("  s:\n    - {Image|endswith: x.exe}\n    - {Image|endswith: y.exe}\n  condition: s")
    assert hit(r, Image="y.exe")
    keywords = rule("  k: [mimikatz, 'sekurlsa::*']\n  condition: k")
    assert hit(keywords, CommandLine="run sekurlsa::logonpasswords")
    null = rule("  s: {ParentImage: null}\n  condition: s")
    assert hit(null) and not hit(null, ParentImage="x")
    cidr = rule("  s: {DestinationIp|cidr: 10.0.0.0/8}\n  condition: s", category="network_connection")
    net = {"EventID": 3, "Channel": "Microsoft-Windows-Sysmon/Operational"}
    assert rule_matches(cidr, prepare_event({**net, "DestinationIp": "10.1.2.3"}))
    assert not rule_matches(cidr, prepare_event({**net, "DestinationIp": "8.8.8.8"}))
    windash = rule("  s: {CommandLine|windash|contains: ' -enc '}\n  condition: s")
    assert hit(windash, CommandLine="powershell /enc AAAA")
    exists = rule("  s: {Hashes|exists: true}\n  condition: s")
    assert hit(exists, Hashes="SHA256=1") and not hit(exists)


def test_logsource_filter_and_security_4688_aliases():
    r = rule("  s: {Image|endswith: '\\cmd.exe'}\n  condition: s")
    assert not rule_matches(r, prepare_event({"EventID": 3, "Channel": "Microsoft-Windows-Sysmon/Operational", "Image": "c:\\cmd.exe"}))
    assert rule_matches(r, prepare_event({"EventID": 4688, "Channel": "Security", "NewProcessName": "C:\\cmd.exe"}))
    assert rule_matches(r, prepare_event({"Image": "C:\\cmd.exe"}))  # generic log without Windows metadata


def test_techniques_from_tags():
    r = rule("  s: {Image: x}\n  condition: s", tags="[attack.execution, attack.t1059.001]")
    assert r.techniques == ["T1059.001"]


@pytest.mark.parametrize(
    "detection,message",
    [
        ("  s: {Image|base64offset: x}\n  condition: s", "Unsupported Sigma modifier"),
        ("  s: {Image: x}\n  condition: s | count() > 5", "aggregation"),
        ("  s: {Image: x}\n  condition: missing", "unknown identifier"),
        ("  s: {Image: x}\n  condition: (s", "Unexpected end"),
    ],
)
def test_unsupported_rules_are_reported(detection, message):
    rules, errors = compile_rules(f"title: bad\nlogsource: {{category: process_creation}}\ndetection:\n{detection}")
    if rules:  # modifier errors surface at evaluation time
        with pytest.raises(SigmaEvalError, match=message):
            rule_matches(rules[0], prepare_event({"Image": "x"}))
    else:
        assert any(message in error for error in errors), errors


def test_catastrophic_regex_times_out_instead_of_hanging():
    r = rule("  s: {CommandLine|re: '(a|aa)+$'}\n  condition: s")
    with pytest.raises(SigmaEvalError, match="timed out"):
        hit(r, CommandLine="a" * 40 + "!")
