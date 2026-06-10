"""Stage 2 (Forensics): log events -> standard Summary.

Extracts event ID frequencies, builds a chronological timeline, and detects
suspicious *sequences* (failed logins -> success -> account creation -> log
clearing), so the AI can interpret the story, not isolated event IDs.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from app.core.schema import Summary, Observation, TimelineEvent, IOCs
from app.modules.forensics.parser import LogEvent

# Security-relevant Windows event IDs with plain-language meaning + MITRE hints
EVENT_CATALOG: dict[int, dict] = {
    4624: {"name": "Successful logon", "sev": "info", "mitre": ["T1078"]},
    4625: {"name": "Failed logon", "sev": "low", "mitre": ["T1110"]},
    4648: {"name": "Logon with explicit credentials", "sev": "low", "mitre": ["T1078"]},
    4672: {"name": "Special privileges assigned to new logon", "sev": "low", "mitre": ["T1078"]},
    4720: {"name": "User account created", "sev": "medium", "mitre": ["T1136.001"]},
    4722: {"name": "User account enabled", "sev": "low", "mitre": ["T1098"]},
    4724: {"name": "Password reset attempt", "sev": "medium", "mitre": ["T1098"]},
    4728: {"name": "Member added to security-enabled global group", "sev": "medium", "mitre": ["T1098"]},
    4732: {"name": "Member added to security-enabled local group", "sev": "medium", "mitre": ["T1098"]},
    4738: {"name": "User account changed", "sev": "low", "mitre": ["T1098"]},
    4756: {"name": "Member added to universal group", "sev": "medium", "mitre": ["T1098"]},
    1102: {"name": "Audit log cleared", "sev": "high", "mitre": ["T1070.001"]},
    104:  {"name": "Event log cleared", "sev": "high", "mitre": ["T1070.001"]},
    7045: {"name": "New service installed", "sev": "medium", "mitre": ["T1543.003"]},
    4697: {"name": "Service installed (security)", "sev": "medium", "mitre": ["T1543.003"]},
    4698: {"name": "Scheduled task created", "sev": "medium", "mitre": ["T1053.005"]},
    4104: {"name": "PowerShell script block executed", "sev": "low", "mitre": ["T1059.001"]},
    4688: {"name": "New process created", "sev": "info", "mitre": ["T1059"]},
    4719: {"name": "System audit policy changed", "sev": "medium", "mitre": ["T1562"]},
    1116: {"name": "Defender malware detected", "sev": "high", "mitre": []},
    5001: {"name": "Defender real-time protection disabled", "sev": "high", "mitre": ["T1562.001"]},
    4778: {"name": "RDP session reconnected", "sev": "low", "mitre": ["T1021.001"]},
    4779: {"name": "RDP session disconnected", "sev": "info", "mitre": ["T1021.001"]},
}


def _parse_ts(ts: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts.strip(), fmt)
        except ValueError:
            continue
    return None


def preprocess(events: list[LogEvent], source_file: str) -> Summary:
    summary = Summary(module="forensics", source_file=source_file)
    obs_counter = 0

    def new_obs(**kwargs) -> Observation:
        nonlocal obs_counter
        obs_counter += 1
        return Observation(id=f"for-{obs_counter:03d}", **kwargs)

    if not events:
        summary.stats = {"events": 0}
        return summary

    events = sorted(events, key=lambda e: e.timestamp)
    id_counts = Counter(e.event_id for e in events)
    accounts = {e.data.get("TargetUserName") for e in events if e.data.get("TargetUserName")}
    source_ips = {e.data.get("IpAddress") for e in events
                  if e.data.get("IpAddress") not in (None, "-", "127.0.0.1", "::1")}

    summary.stats = {
        "events": len(events),
        "unique_event_ids": len(id_counts),
        "first_event": events[0].timestamp,
        "last_event": events[-1].timestamp,
        "event_id_frequency": {
            str(eid): {"count": count,
                       "meaning": EVENT_CATALOG.get(eid, {}).get("name", "uncatalogued")}
            for eid, count in id_counts.most_common(40)
        },
        "computers": sorted({e.computer for e in events if e.computer})[:10],
    }
    summary.iocs = IOCs(
        ips=sorted(ip for ip in source_ips if ip)[:30],
        accounts=sorted(a for a in accounts if a)[:30],
    )

    # ---- Single-event detections (high-signal IDs) -------------------------
    for eid, count in id_counts.items():
        info = EVENT_CATALOG.get(eid)
        if info and info["sev"] in ("medium", "high"):
            instances = [e for e in events if e.event_id == eid]
            detail_bits = []
            for e in instances[:3]:
                who = e.data.get("TargetUserName") or e.data.get("SubjectUserName") or ""
                svc = e.data.get("ServiceName") or e.data.get("TaskName") or ""
                if who or svc:
                    detail_bits.append(f"{who}{('/' + svc) if svc else ''}")
            summary.observations.append(new_obs(
                type="notable_event",
                description=(f"Event {eid} ({info['name']}) occurred {count}x"
                             + (f" — involving: {', '.join(detail_bits)}" if detail_bits else "")),
                severity_hint=info["sev"],
                data={"event_id": eid, "count": count, "meaning": info["name"]},
                timestamps=[e.timestamp for e in instances[:5]],
                mitre_hints=info["mitre"],
            ))

    # ---- Sequence detections ------------------------------------------------
    # 1. Brute force: burst of 4625 then a 4624 for the same account
    fails_by_account: dict[str, list[LogEvent]] = defaultdict(list)
    for e in events:
        if e.event_id == 4625:
            fails_by_account[e.data.get("TargetUserName", "?")].append(e)
    for account, fails in fails_by_account.items():
        if len(fails) < 5:
            continue
        last_fail_ts = fails[-1].timestamp
        success = next((e for e in events if e.event_id == 4624
                        and e.data.get("TargetUserName") == account
                        and e.timestamp > last_fail_ts), None)
        if success:
            summary.observations.append(new_obs(
                type="brute_force_success",
                description=(f"{len(fails)} failed logons for account '{account}' followed by "
                             f"a SUCCESSFUL logon at {success.timestamp} — credential attack "
                             "that likely succeeded"),
                severity_hint="critical",
                data={"account": account, "failed_attempts": len(fails),
                      "success_time": success.timestamp,
                      "source_ips": sorted({f.data.get('IpAddress', '?') for f in fails})[:5]},
                timestamps=[fails[0].timestamp, success.timestamp],
                mitre_hints=["T1110", "T1078"],
            ))
        else:
            summary.observations.append(new_obs(
                type="brute_force_attempt",
                description=f"{len(fails)} failed logons for account '{account}' (no success seen)",
                severity_hint="medium",
                data={"account": account, "failed_attempts": len(fails)},
                timestamps=[fails[0].timestamp, fails[-1].timestamp],
                mitre_hints=["T1110"],
            ))

    # 2. Privilege escalation chain: logon -> account created -> added to admin group
    creation = next((e for e in events if e.event_id == 4720), None)
    group_add = next((e for e in events if e.event_id in (4728, 4732, 4756)), None)
    if creation and group_add and group_add.timestamp >= creation.timestamp:
        summary.observations.append(new_obs(
            type="privilege_escalation_chain",
            description=(f"Account '{creation.data.get('TargetUserName', '?')}' was created "
                         f"at {creation.timestamp} and added to a privileged group at "
                         f"{group_add.timestamp} — classic persistence/escalation sequence"),
            severity_hint="critical",
            data={"account": creation.data.get("TargetUserName", "?"),
                  "created": creation.timestamp, "elevated": group_add.timestamp},
            timestamps=[creation.timestamp, group_add.timestamp],
            mitre_hints=["T1136.001", "T1098", "T1078"],
        ))

    # 3. Cover-up: log cleared after suspicious activity
    log_clear = next((e for e in events if e.event_id in (1102, 104)), None)
    if log_clear and len(summary.observations) > 0:
        summary.observations.append(new_obs(
            type="log_clearing_coverup",
            description=(f"Event log was CLEARED at {log_clear.timestamp}, after other "
                         "suspicious activity in this log — strong indicator of deliberate "
                         "cover-up rather than routine maintenance"),
            severity_hint="critical",
            data={"cleared_at": log_clear.timestamp,
                  "by": log_clear.data.get("SubjectUserName", "?")},
            timestamps=[log_clear.timestamp],
            mitre_hints=["T1070.001"],
        ))

    # 4. Off-hours activity (between 00:00 and 05:00 local log time)
    off_hours = [e for e in events
                 if (dt := _parse_ts(e.timestamp)) and dt.hour < 5
                 and EVENT_CATALOG.get(e.event_id, {}).get("sev") in ("medium", "high")]
    if off_hours:
        summary.observations.append(new_obs(
            type="off_hours_activity",
            description=(f"{len(off_hours)} security-relevant events occurred between "
                         "midnight and 05:00 — unusual timing for administrative actions"),
            severity_hint="medium",
            data={"count": len(off_hours),
                  "event_ids": sorted({e.event_id for e in off_hours})},
            timestamps=[off_hours[0].timestamp],
        ))

    # ---- Timeline: every catalogued event, in order -------------------------
    for e in events:
        info = EVENT_CATALOG.get(e.event_id)
        if info and (info["sev"] != "info" or id_counts[e.event_id] <= 20):
            who = e.data.get("TargetUserName") or e.data.get("SubjectUserName") or ""
            summary.timeline.append(TimelineEvent(
                timestamp=e.timestamp,
                event=f"{e.event_id} {info['name']}",
                detail=f"account: {who}" if who else "",
                severity=info["sev"],
            ))
    summary.timeline = summary.timeline[:200]
    return summary
