"""The standard JSON "summary" contract that EVERY module's pre-processor outputs.

This is the heart of the pipeline architecture:

    Raw File -> Parser -> Pre-processor -> [Summary] -> AI Analysis -> Scoring -> Playbook -> Dashboard

Because all three modules (network / forensics / malware) emit the same Summary
shape, the AI engine, scoring, playbook generator, and dashboard never need to
know what kind of file was analyzed. New file types = new pre-processor only.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"

SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Observation:
    """One noteworthy thing the pre-processor extracted (NOT yet a verdict —
    the AI decides what observations mean in combination)."""
    id: str
    type: str                       # e.g. "beaconing", "event_sequence", "high_entropy_section"
    description: str                # human-readable, plain language
    severity_hint: str = "info"     # pre-processor's heuristic guess; AI may override
    data: dict[str, Any] = field(default_factory=dict)
    timestamps: list[str] = field(default_factory=list)
    mitre_hints: list[str] = field(default_factory=list)  # technique IDs e.g. ["T1071"]


@dataclass
class TimelineEvent:
    timestamp: str
    event: str
    detail: str = ""
    severity: str = "info"


@dataclass
class IOCs:
    """Indicators of Compromise collected by the pre-processor."""
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)


@dataclass
class Summary:
    """The standard pre-processor output. Compact enough for an AI context
    window, rich enough for accurate analysis."""
    module: str                     # "network" | "forensics" | "malware"
    source_file: str
    stats: dict[str, Any] = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    iocs: IOCs = field(default_factory=IOCs)
    enrichment: dict[str, Any] = field(default_factory=dict)  # threat-intel lookups
    schema_version: str = SCHEMA_VERSION
    generated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """One AI-produced conclusion."""
    title: str
    description: str
    severity: str                   # one of SEVERITY_LEVELS
    confidence: float               # 0.0 - 1.0
    evidence: list[str] = field(default_factory=list)      # observation ids
    mitre_tactics: list[str] = field(default_factory=list)  # e.g. ["TA0011"]
    mitre_techniques: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)


@dataclass
class Report:
    """Final pipeline output consumed by the dashboard."""
    analysis_id: str
    module: str
    source_file: str
    summary: dict                   # the Summary (as dict)
    findings: list[dict]            # list of Finding dicts
    narrative: str                  # AI plain-language story of what happened
    score: int                      # 0-100
    severity: str                   # overall level
    severity_distribution: dict[str, int]
    mitre: list[dict]               # [{tactic_id, tactic_name, techniques: [...]}]
    playbook: list[dict]            # ordered investigation steps
    soar_actions: list[dict]        # tiered response actions
    generated_at: str = field(default_factory=now_iso)
    ai_provider: str = "mock"
    usage: dict = field(default_factory=dict)   # token + cost accounting
    cached: bool = False                         # served from AI response cache

    def to_dict(self) -> dict:
        return asdict(self)


def validate_severity(value: str) -> str:
    v = (value or "info").lower().strip()
    return v if v in SEVERITY_LEVELS else "info"
