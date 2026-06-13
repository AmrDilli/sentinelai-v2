"""MITRE ATT&CK reference data and mapping helpers.

A curated subset of the Enterprise matrix covering the tactics/techniques this
platform can realistically detect. Technique -> tactic mapping lets every
module report findings on the same matrix.
"""
from __future__ import annotations

TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

# technique_id -> (name, [tactic_ids])
TECHNIQUES = {
    "T1071": ("Application Layer Protocol", ["TA0011"]),
    "T1071.001": ("Web Protocols (C2)", ["TA0011"]),
    "T1071.004": ("DNS (C2)", ["TA0011"]),
    "T1095": ("Non-Application Layer Protocol", ["TA0011"]),
    "T1571": ("Non-Standard Port", ["TA0011"]),
    "T1573": ("Encrypted Channel", ["TA0011"]),
    "T1572": ("Protocol Tunneling", ["TA0011"]),
    "T1041": ("Exfiltration Over C2 Channel", ["TA0010"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["TA0010"]),
    "T1110": ("Brute Force", ["TA0006"]),
    "T1110.001": ("Password Guessing", ["TA0006"]),
    "T1078": ("Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1136": ("Create Account", ["TA0003"]),
    "T1136.001": ("Create Local Account", ["TA0003"]),
    "T1098": ("Account Manipulation", ["TA0003"]),
    "T1070": ("Indicator Removal", ["TA0005"]),
    "T1070.001": ("Clear Windows Event Logs", ["TA0005"]),
    "T1562": ("Impair Defenses", ["TA0005"]),
    "T1562.001": ("Disable or Modify Tools", ["TA0005"]),
    "T1059": ("Command and Scripting Interpreter", ["TA0002"]),
    "T1059.001": ("PowerShell", ["TA0002"]),
    "T1053": ("Scheduled Task/Job", ["TA0002", "TA0003", "TA0004"]),
    "T1053.005": ("Scheduled Task", ["TA0002", "TA0003", "TA0004"]),
    "T1543": ("Create or Modify System Process", ["TA0003", "TA0004"]),
    "T1543.003": ("Windows Service", ["TA0003", "TA0004"]),
    "T1021": ("Remote Services", ["TA0008"]),
    "T1021.001": ("Remote Desktop Protocol", ["TA0008"]),
    "T1021.002": ("SMB/Windows Admin Shares", ["TA0008"]),
    "T1046": ("Network Service Discovery", ["TA0007"]),
    "T1018": ("Remote System Discovery", ["TA0007"]),
    "T1027": ("Obfuscated Files or Information", ["TA0005"]),
    "T1027.002": ("Software Packing", ["TA0005"]),
    "T1553.002": ("Code Signing (abused/invalid)", ["TA0005"]),
    "T1105": ("Ingress Tool Transfer", ["TA0011"]),
    "T1568": ("Dynamic Resolution", ["TA0011"]),
    "T1568.002": ("Domain Generation Algorithms", ["TA0011"]),
    "T1486": ("Data Encrypted for Impact (Ransomware)", ["TA0040"]),
    "T1489": ("Service Stop", ["TA0040"]),
    "T1490": ("Inhibit System Recovery", ["TA0040"]),
    "T1056": ("Input Capture", ["TA0006", "TA0009"]),
    "T1056.001": ("Keylogging", ["TA0006", "TA0009"]),
    "T1547": ("Boot or Logon Autostart Execution", ["TA0003", "TA0004"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["TA0003", "TA0004"]),
    "T1204": ("User Execution", ["TA0002"]),
    "T1566": ("Phishing", ["TA0001"]),
    "T1190": ("Exploit Public-Facing Application", ["TA0001"]),
    "T1003": ("OS Credential Dumping", ["TA0006"]),
    "T1110.003": ("Password Spraying", ["TA0006"]),
}


def technique_name(tid: str) -> str:
    entry = TECHNIQUES.get(tid)
    return entry[0] if entry else tid


def tactics_for_technique(tid: str) -> list[str]:
    entry = TECHNIQUES.get(tid)
    if entry:
        return entry[1]
    # Try parent technique for unknown sub-techniques (T1234.001 -> T1234)
    parent = tid.split(".")[0]
    entry = TECHNIQUES.get(parent)
    return entry[1] if entry else []


def build_matrix(findings: list[dict]) -> list[dict]:
    """Group all techniques referenced by findings into a tactic -> techniques
    structure the dashboard renders as an ATT&CK matrix."""
    tactic_map: dict[str, dict] = {}
    # Track which technique ids we've already placed under each tactic, and which
    # findings reference each technique, so the UI can show one chip per technique
    # with the count of supporting findings rather than duplicates.
    seen: dict[tuple, dict] = {}
    for finding in findings:
        techniques = finding.get("mitre_techniques", []) or []
        explicit_tactics = finding.get("mitre_tactics", []) or []
        for tid in techniques:
            for ta in tactics_for_technique(tid) or explicit_tactics:
                bucket = tactic_map.setdefault(
                    ta, {"tactic_id": ta, "tactic_name": TACTICS.get(ta, ta), "techniques": []}
                )
                key = (ta, tid)
                if key in seen:
                    seen[key]["findings"].append(finding.get("title", ""))
                else:
                    tech = {"id": tid, "name": technique_name(tid),
                            "findings": [finding.get("title", "")]}
                    seen[key] = tech
                    bucket["techniques"].append(tech)
        for ta in explicit_tactics:
            tactic_map.setdefault(
                ta, {"tactic_id": ta, "tactic_name": TACTICS.get(ta, ta), "techniques": []}
            )
    # Order by kill-chain position (tactic id)
    return [tactic_map[k] for k in sorted(tactic_map)]
