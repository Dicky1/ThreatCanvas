"""Parses uploaded log datasets into flat event dicts for Sigma evaluation.

Supported inputs:
- OTRF Security-Datasets (Mordor): JSON lines, usually inside .zip / .tar.gz
- Atomic Red Team / Windows event logs: .evtx
- Winlogbeat / Elastic exports: JSON or NDJSON with ``winlog.event_data``
- generic JSON array / JSON lines of flat events

All archive handling happens in memory with strict limits on compressed
size, uncompressed size, member count and event count (zip-bomb safe); no
file from an archive is ever written to disk.
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
import zipfile
from collections.abc import Iterator
from typing import Any

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 200
MAX_EVENTS = 50_000
MAX_FIELD_CHARS = 4_096
LOG_EXTENSIONS = (".json", ".jsonl", ".ndjson", ".log", ".txt", ".evtx")


class DatasetError(ValueError):
    """The upload cannot be parsed or exceeds a limit."""


def _limited_read(stream, budget: list[int], name: str) -> bytes:
    """Read a stream while charging the shared uncompressed-size budget."""
    chunks = []
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        budget[0] -= len(chunk)
        if budget[0] < 0:
            raise DatasetError(f"Uncompressed dataset exceeds {MAX_UNCOMPRESSED_BYTES // (1024 * 1024)} MB ({name})")
        chunks.append(chunk)
    return b"".join(chunks)


def _scalar(value: Any) -> Any:
    if isinstance(value, dict):
        if "#text" in value:
            return value["#text"]
        if "Value" in value and len(value) <= 2:
            return value["Value"]
    if isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
        return value[:MAX_FIELD_CHARS]
    return value


def _flatten_dotted(prefix: str, value: Any, out: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _flatten_dotted(f"{prefix}.{key}" if prefix else str(key), item, out)
    elif not isinstance(value, list):
        out.setdefault(prefix, _scalar(value))


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Map common Windows log shapes onto flat Sysmon-style field names."""
    event: dict[str, Any] = {}

    # EVTX (python evtx): {"Event": {"System": {...}, "EventData": {...}}}
    root = raw.get("Event") if isinstance(raw.get("Event"), dict) else None
    if root is not None:
        system = root.get("System") or {}
        event["EventID"] = _scalar(system.get("EventID"))
        event["Channel"] = _scalar(system.get("Channel"))
        event["Computer"] = _scalar(system.get("Computer"))
        provider = system.get("Provider")
        if isinstance(provider, dict):
            event["Provider"] = (provider.get("#attributes") or {}).get("Name")
        for section in ("EventData", "UserData"):
            data = root.get(section)
            if isinstance(data, dict):
                for key, value in data.items():
                    if key != "#attributes" and not isinstance(value, (dict, list)):
                        event[key] = _scalar(value)
        return {k: v for k, v in event.items() if v is not None}

    # Winlogbeat / Elastic: {"winlog": {"event_id", "channel", "event_data"}}
    winlog = raw.get("winlog") if isinstance(raw.get("winlog"), dict) else None
    if winlog is not None:
        event["EventID"] = _scalar(winlog.get("event_id"))
        event["Channel"] = _scalar(winlog.get("channel"))
        event["Computer"] = _scalar(winlog.get("computer_name"))
        for key, value in (winlog.get("event_data") or {}).items():
            if not isinstance(value, (dict, list)):
                event[key] = _scalar(value)
        dotted: dict[str, Any] = {}
        _flatten_dotted("", {k: v for k, v in raw.items() if k != "winlog"}, dotted)
        for key, value in dotted.items():
            event.setdefault(key, value)
        return {k: v for k, v in event.items() if v is not None}

    # OTRF / generic: already flat; flatten any nested objects with dots.
    _flatten_dotted("", raw, event)
    return {k: v for k, v in event.items() if v is not None}


def _json_events(text: str) -> Iterator[dict[str, Any]]:
    stripped = text.lstrip()
    if not stripped:
        return
    if stripped[0] in "[{":
        try:
            document = json.loads(stripped)
        except json.JSONDecodeError:
            document = None
        if isinstance(document, list):
            yield from (item for item in document if isinstance(item, dict))
            return
        if isinstance(document, dict):
            # Elastic search response: {"hits": {"hits": [{"_source": {...}}]}}
            hits = (document.get("hits") or {}).get("hits") if isinstance(document.get("hits"), dict) else None
            if isinstance(hits, list):
                yield from (h.get("_source", h) for h in hits if isinstance(h, dict))
            else:
                yield document
            return
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as error:
            raise DatasetError(f"Line {number} is not valid JSON") from error
        if isinstance(item, dict):
            yield item


def _evtx_events(data: bytes) -> Iterator[dict[str, Any]]:
    try:
        from evtx import PyEvtxParser
    except ImportError as error:  # pragma: no cover - dependency is pinned
        raise DatasetError("EVTX support is not installed") from error
    try:
        parser = PyEvtxParser(io.BytesIO(data))
        for record in parser.records_json():
            try:
                yield json.loads(record["data"])
            except (KeyError, json.JSONDecodeError):
                continue
    except (OSError, RuntimeError) as error:
        raise DatasetError(f"Invalid EVTX file: {error}") from error


def _member_events(name: str, data: bytes) -> Iterator[dict[str, Any]]:
    lowered = name.lower()
    if lowered.endswith(".evtx"):
        yield from _evtx_events(data)
    elif lowered.endswith(LOG_EXTENSIONS):
        yield from _json_events(data.decode("utf-8", errors="replace"))


def _archive_members(filename: str, data: bytes) -> Iterator[tuple[str, bytes]]:
    budget = [MAX_UNCOMPRESSED_BYTES]
    lowered = filename.lower()
    if lowered.endswith(".zip"):
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as error:
            raise DatasetError("Invalid ZIP archive") from error
        members = [info for info in archive.infolist() if not info.is_dir()]
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise DatasetError(f"Archive has more than {MAX_ARCHIVE_MEMBERS} files")
        for info in members:
            if info.file_size > MAX_UNCOMPRESSED_BYTES:
                raise DatasetError(f"{info.filename} is too large when uncompressed")
            if not info.filename.lower().endswith(LOG_EXTENSIONS):
                continue
            with archive.open(info) as stream:  # declared sizes can lie: read with budget
                yield info.filename, _limited_read(stream, budget, info.filename)
        return
    if lowered.endswith((".tar.gz", ".tgz", ".tar")):
        try:
            archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        except tarfile.TarError as error:
            raise DatasetError("Invalid TAR archive") from error
        count = 0
        for member in archive:
            if not member.isfile():
                continue  # skips symlinks/devices: nothing is extracted to disk anyway
            count += 1
            if count > MAX_ARCHIVE_MEMBERS:
                raise DatasetError(f"Archive has more than {MAX_ARCHIVE_MEMBERS} files")
            if not member.name.lower().endswith(LOG_EXTENSIONS):
                continue
            stream = archive.extractfile(member)
            if stream is not None:
                yield member.name, _limited_read(stream, budget, member.name)
        return
    if lowered.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            yield filename[:-3], _limited_read(stream, budget, filename)
        return
    yield filename, data


def parse_dataset(filename: str, data: bytes) -> list[dict[str, Any]]:
    """Return normalized events. Raises DatasetError on bad input/limits."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise DatasetError(f"Upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    filename = filename or "upload.json"
    archive_ext = (".zip", ".tar.gz", ".tgz", ".tar", ".gz")
    if not filename.lower().endswith(archive_ext + LOG_EXTENSIONS):
        filename += ".json"  # unknown extension: assume JSON / JSON lines
    events: list[dict[str, Any]] = []
    try:
        for name, member in _archive_members(filename, data):
            for raw in _member_events(name, member):
                events.append(normalize_event(raw))
                if len(events) > MAX_EVENTS:
                    raise DatasetError(f"Dataset has more than {MAX_EVENTS} events; split it into smaller files")
    except (EOFError, gzip.BadGzipFile, zipfile.BadZipFile, tarfile.TarError) as error:
        raise DatasetError(f"Corrupt archive: {error}") from error
    if not events:
        raise DatasetError(
            "No events found. Supported: .json/.jsonl/.ndjson/.evtx, or .zip/.tar.gz containing them."
        )
    return events
