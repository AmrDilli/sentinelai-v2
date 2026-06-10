"""Stage 1 (Forensics): Windows event logs -> event records.

Accepts three input formats:
  .evtx   — native binary log (requires optional `python-evtx` package)
  .xml    — Event Viewer "Save As XML" export (stdlib)
  .jsonl  — one JSON event per line, e.g. from `evtx_dump --format jsonl` (stdlib)
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LogEvent:
    event_id: int
    timestamp: str                 # ISO 8601
    provider: str = ""
    computer: str = ""
    data: dict[str, str] = field(default_factory=dict)  # EventData fields


def parse_log(path: str) -> list[LogEvent]:
    suffix = Path(path).suffix.lower()
    if suffix == ".evtx":
        return _parse_evtx(path)
    if suffix == ".xml":
        return _parse_xml(Path(path).read_text(encoding="utf-8", errors="replace"))
    if suffix in (".jsonl", ".json"):
        return _parse_jsonl(path)
    raise ValueError(f"Unsupported log format '{suffix}'. Use .evtx, .xml, or .jsonl")


def _parse_evtx(path: str) -> list[LogEvent]:
    try:
        from Evtx.Evtx import Evtx  # optional dependency
    except ImportError as exc:
        raise RuntimeError(
            "Parsing .evtx requires python-evtx (pip install python-evtx). "
            "Alternatively export the log as XML or JSONL."
        ) from exc
    events = []
    with Evtx(path) as log:
        for record in log.records():
            try:
                events.append(_event_from_xml_element(ET.fromstring(record.xml())))
            except ET.ParseError:
                continue
    return [e for e in events if e]


_NS = re.compile(r"\{.*?\}")


def _strip_ns(tag: str) -> str:
    return _NS.sub("", tag)


def _event_from_xml_element(root: ET.Element) -> LogEvent | None:
    event_id, timestamp, provider, computer, data = 0, "", "", "", {}
    for el in root.iter():
        tag = _strip_ns(el.tag)
        if tag == "EventID" and el.text:
            try:
                event_id = int(el.text.strip())
            except ValueError:
                pass
        elif tag == "TimeCreated":
            timestamp = el.get("SystemTime", "")
        elif tag == "Provider":
            provider = el.get("Name", "")
        elif tag == "Computer" and el.text:
            computer = el.text.strip()
        elif tag == "Data":
            name = el.get("Name")
            if name and el.text:
                data[name] = el.text.strip()
    if not event_id:
        return None
    return LogEvent(event_id=event_id, timestamp=timestamp, provider=provider,
                    computer=computer, data=data)


def _parse_xml(text: str) -> list[LogEvent]:
    # Event Viewer exports may be a list of <Event> elements without one root
    if "<Events" not in text:
        text = f"<Events>{text}</Events>"
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML log export: {exc}") from exc
    events = []
    for ev in root.iter():
        if _strip_ns(ev.tag) == "Event":
            parsed = _event_from_xml_element(ev)
            if parsed:
                events.append(parsed)
    return events


def _parse_jsonl(path: str) -> list[LogEvent]:
    events = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Support both flat records and evtx_dump-style {"Event": {"System": ...}}
        sysblock = rec.get("Event", {}).get("System", rec)
        evdata = rec.get("Event", {}).get("EventData", rec.get("EventData", {})) or {}
        eid = sysblock.get("EventID", rec.get("event_id", 0))
        if isinstance(eid, dict):  # evtx_dump renders as {"#text": 4624}
            eid = eid.get("#text", 0)
        ts = sysblock.get("TimeCreated", {})
        if isinstance(ts, dict):
            ts = ts.get("#attributes", {}).get("SystemTime", "") or ts.get("SystemTime", "")
        ts = ts or rec.get("timestamp", "")
        provider = sysblock.get("Provider", {})
        if isinstance(provider, dict):
            provider = provider.get("#attributes", {}).get("Name", "") or provider.get("Name", "")
        try:
            eid = int(eid)
        except (TypeError, ValueError):
            continue
        if eid:
            events.append(LogEvent(
                event_id=eid, timestamp=str(ts),
                provider=str(provider or rec.get("provider", "")),
                computer=str(sysblock.get("Computer", rec.get("computer", ""))),
                data={k: str(v) for k, v in evdata.items() if v is not None},
            ))
    return events
