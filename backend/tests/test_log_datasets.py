import io
import json
import tarfile
import zipfile

import pytest

from app.services import log_datasets
from app.services.log_datasets import DatasetError, normalize_event, parse_dataset

OTRF_LINE = {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Image": "C:\\wscript.exe",
             "CommandLine": "wscript launcher.vbs", "Message": "x" * 10_000}


def jsonl(*events):
    return "\n".join(json.dumps(e) for e in events).encode()


def zipped(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_otrf_json_lines_in_zip_and_long_fields_truncated():
    events = parse_dataset("dataset.zip", zipped({"sub/dataset.json": jsonl(OTRF_LINE, OTRF_LINE), "README.md": b"skip"}))
    assert len(events) == 2
    assert events[0]["Image"] == "C:\\wscript.exe"
    assert len(events[0]["Message"]) == log_datasets.MAX_FIELD_CHARS


def test_tar_gz_json_array_and_unknown_extension():
    buffer = io.BytesIO()
    payload = json.dumps([OTRF_LINE]).encode()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("logs/data.json")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
        link = tarfile.TarInfo("logs/evil.json")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        archive.addfile(link)
    assert len(parse_dataset("d.tar.gz", buffer.getvalue())) == 1
    assert len(parse_dataset("export", jsonl(OTRF_LINE))) == 1


def test_winlogbeat_and_evtx_shapes_are_normalized():
    winlogbeat = normalize_event({
        "winlog": {"event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational",
                   "event_data": {"Image": "C:\\a.exe", "CommandLine": "a"}},
        "host": {"name": "WS1"},
    })
    assert winlogbeat["EventID"] == 1 and winlogbeat["Image"] == "C:\\a.exe" and winlogbeat["host.name"] == "WS1"
    evtx = normalize_event({"Event": {
        "System": {"EventID": {"#text": 1}, "Channel": "Microsoft-Windows-Sysmon/Operational",
                   "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}}},
        "EventData": {"Image": "C:\\b.exe", "#attributes": {"x": 1}},
    }})
    assert evtx == {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                    "Provider": "Microsoft-Windows-Sysmon", "Image": "C:\\b.exe"}


def test_evtx_upload_uses_parser(monkeypatch):
    import evtx

    class FakeParser:
        def __init__(self, stream):
            assert stream.read(4) == b"ElfF"

        def records_json(self):
            yield {"data": json.dumps({"Event": {"System": {"EventID": 1, "Channel": "Security"}, "EventData": {"Image": "x"}}})}

    monkeypatch.setattr(evtx, "PyEvtxParser", FakeParser)
    assert parse_dataset("art.evtx", b"ElfFile...") == [{"EventID": 1, "Channel": "Security", "Image": "x"}]


def test_zip_bomb_is_rejected_by_uncompressed_budget(monkeypatch):
    monkeypatch.setattr(log_datasets, "MAX_UNCOMPRESSED_BYTES", 50_000)
    bomb = zipped({"a.json": jsonl(OTRF_LINE) * 0 + b" " * 200_000})
    with pytest.raises(DatasetError, match="too large|exceeds"):
        parse_dataset("bomb.zip", bomb)


def test_limits(monkeypatch):
    monkeypatch.setattr(log_datasets, "MAX_ARCHIVE_MEMBERS", 2)
    with pytest.raises(DatasetError, match="more than 2 files"):
        parse_dataset("many.zip", zipped({f"{i}.json": b"{}" for i in range(3)}))
    monkeypatch.setattr(log_datasets, "MAX_EVENTS", 2)
    with pytest.raises(DatasetError, match="more than 2 events"):
        parse_dataset("e.jsonl", jsonl(OTRF_LINE, OTRF_LINE, OTRF_LINE))
    with pytest.raises(DatasetError, match="No events"):
        parse_dataset("empty.json", b"   ")
    with pytest.raises(DatasetError, match="Line 2"):
        parse_dataset("bad.jsonl", b'{"a": 1}\nnot json')
    with pytest.raises(DatasetError, match="Invalid ZIP"):
        parse_dataset("x.zip", b"not a zip")
