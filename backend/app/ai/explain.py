"""Per-finding "Explain this" drill-down.

Turns a single finding into an analyst-grade writeup a junior can learn from
and an expert respects. With a real provider it asks the model for a tailored
explanation; under the offline mock it composes a structured, genuinely useful
template from the finding's own fields plus MITRE context — so the feature
works (and demos) with no API key.
"""
from __future__ import annotations

import json

from app.ai.provider import get_provider, MockProvider
from app.core.mitre import TACTICS, technique_name, tactics_for_technique

SYSTEM_PROMPT = """You are SentinelAI, a senior SOC analyst mentoring a junior. You are given ONE
finding plus the surrounding case context. Write a clear, structured drill-down a learner can
follow but an expert respects. Use these short headers, each with 1-3 sentences:

What this means
Why it matters
How the attacker does this
How to confirm it
Recommended response

Be specific to the evidence (names, IPs, accounts, timestamps, hashes where present). Keep it
150-300 words, plain prose under the headers, no JSON, no preamble."""

_CONFIRM = {
    "network": ("Pivot on the destination IP/domain and port in your flow logs, proxy, and "
                "DNS records; line up the timing against the beacon interval and look for the "
                "same pattern from peer hosts."),
    "forensics": ("Pull the raw event records around the listed timestamps, confirm the source "
                  "host and account, and hunt the same event-ID sequence across other endpoints."),
    "malware": ("Re-hash the sample and check the hashes against VirusTotal, inspect the flagged "
                "sections/strings, and detonate in an isolated sandbox to confirm behaviour."),
}


def _template_explanation(report: dict, finding: dict) -> str:
    module = report.get("module", "")
    sev = (finding.get("severity") or "info").upper()
    conf = int(round(float(finding.get("confidence", 0)) * 100))
    techs = finding.get("mitre_techniques", []) or []
    tech_lines = ", ".join(f"{t} ({technique_name(t)})" for t in techs) or "none mapped"
    tactics = sorted({ta for t in techs for ta in tactics_for_technique(t)})
    tactic_names = ", ".join(TACTICS.get(t, t) for t in tactics) or "general suspicious activity"
    remediation = finding.get("remediation", []) or []
    rem_text = (" ".join(f"{i + 1}. {r}" for i, r in enumerate(remediation))
                or "Scope the activity, confirm whether it is authorized, and contain affected assets.")
    confirm = _CONFIRM.get(module, "Correlate this finding against your other telemetry and "
                                    "confirm whether the activity was authorized.")
    return (
        "What this means\n"
        f"{finding.get('description', '').strip() or finding.get('title', '')}\n\n"
        "Why it matters\n"
        f"This is rated {sev} severity at {conf}% confidence. Left unaddressed it advances the "
        f"attacker along the ATT&CK tactics: {tactic_names}.\n\n"
        "How the attacker does this\n"
        f"The behaviour maps to {tech_lines}. These techniques let an adversary operate while "
        "blending into normal activity, which is why detection leans on behavioural patterns "
        "rather than a single signature.\n\n"
        "How to confirm it\n"
        f"{confirm}\n\n"
        "Recommended response\n"
        f"{rem_text}"
    )


def explain_finding(report: dict, index: int) -> dict:
    """Return {finding_title, explanation, ai_provider} for one finding."""
    findings = report.get("findings", []) or []
    if not 0 <= index < len(findings):
        raise IndexError("finding index out of range")
    finding = findings[index]
    provider = get_provider()

    if isinstance(provider, MockProvider):
        return {
            "finding_title": finding.get("title", ""),
            "explanation": _template_explanation(report, finding),
            "ai_provider": provider.name,
        }

    context = {
        "module": report.get("module"),
        "narrative": report.get("narrative"),
        "overall_severity": report.get("severity"),
        "other_findings": [f.get("title") for i, f in enumerate(findings) if i != index][:8],
    }
    user_prompt = ("CASE CONTEXT:\n" + json.dumps(context, indent=1)
                   + "\n\nFINDING TO EXPLAIN:\n" + json.dumps(finding, indent=1))
    try:
        text = provider.complete(SYSTEM_PROMPT, user_prompt).strip()
    except Exception as exc:  # fall back to the deterministic writeup
        text = _template_explanation(report, finding) + f"\n\n(Live AI expansion unavailable: {exc})"
    return {
        "finding_title": finding.get("title", ""),
        "explanation": text,
        "ai_provider": provider.name,
    }
