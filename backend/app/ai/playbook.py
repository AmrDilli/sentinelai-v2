"""Stage 5: AI-generated investigation playbook.

Takes the findings (optionally from MULTIPLE analyses — cross-module
correlation) and produces an ordered, tailored investigation guide.
"""
from __future__ import annotations

import json

from app.ai.provider import get_provider, MockProvider

SYSTEM_PROMPT = """You are SentinelAI's incident response planner. Given the findings of one or
more analyses (possibly spanning network, forensics, and malware modules), produce a
single ordered investigation playbook tailored to this exact combination of findings.

Rules:
- Order steps by investigative priority (verify -> scope -> contain -> eradicate -> recover).
- Where findings from different modules connect (e.g. network beaconing + a new admin
  account created at the same time), say so explicitly and unify the investigation path.
- Each step must be concrete: name the tool/log/command/account/IP to look at.
- Include "expected_outcome" so a junior analyst knows what confirms or clears the step.

Respond ONLY with JSON:
{
  "playbook": [
    {
      "step": 1,
      "phase": "verify|scope|contain|eradicate|recover",
      "title": "short imperative title",
      "instructions": "concrete instructions referencing specific evidence",
      "expected_outcome": "what confirms or rules out the threat",
      "related_findings": ["finding titles"]
    }
  ]
}"""


def generate_playbook(analyses: list[dict]) -> list[dict]:
    """analyses: list of {"module": ..., "findings": [...], "narrative": ...}."""
    significant = [
        f for a in analyses for f in a.get("findings", [])
        if f.get("severity") in ("low", "medium", "high", "critical")
    ]
    if not significant:
        return [{
            "step": 1, "phase": "verify", "title": "Routine review",
            "instructions": "No significant findings. Archive the report and confirm "
                            "monitoring coverage is healthy.",
            "expected_outcome": "Report archived.", "related_findings": [],
        }]

    provider = get_provider()
    if isinstance(provider, MockProvider):
        return _heuristic_playbook(significant)

    user_prompt = "ANALYSES:\n" + json.dumps(
        [{"module": a.get("module"), "narrative": a.get("narrative"),
          "findings": a.get("findings")} for a in analyses], indent=1)
    try:
        result = provider.complete_json(SYSTEM_PROMPT, user_prompt)
        steps = result.get("playbook", [])
        return [s for s in steps if isinstance(s, dict)][:15] or _heuristic_playbook(significant)
    except Exception:
        return _heuristic_playbook(significant)


def _heuristic_playbook(findings: list[dict]) -> list[dict]:
    """Deterministic fallback so the dashboard always has a playbook."""
    steps = []
    ordered = sorted(findings, key=lambda f: ["critical", "high", "medium", "low"]
                     .index(f["severity"]) if f["severity"] in
                     ("critical", "high", "medium", "low") else 9)
    for i, f in enumerate(ordered[:8], start=1):
        steps.append({
            "step": i,
            "phase": "verify" if i <= 2 else "scope" if i <= 4 else "contain",
            "title": f"Investigate: {f['title']}",
            "instructions": (f"{f['description']} Review evidence "
                             f"({', '.join(f.get('evidence', [])) or 'see summary'}) and "
                             "confirm whether this activity was authorized. "
                             + " ".join(f.get("remediation", [])[:2])),
            "expected_outcome": "Activity confirmed malicious (continue playbook) or "
                                "explained as legitimate (close finding).",
            "related_findings": [f["title"]],
        })
    steps.append({
        "step": len(steps) + 1, "phase": "recover",
        "title": "Document and harden",
        "instructions": "Write up the incident timeline, update detection rules for the "
                        "techniques observed, and brief the team.",
        "expected_outcome": "Lessons captured; detections improved.",
        "related_findings": [],
    })
    return steps
