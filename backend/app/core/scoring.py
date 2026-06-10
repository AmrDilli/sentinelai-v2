"""Severity scoring.

Combines AI finding severities and confidences into a single 0-100 score.
Sequence matters: multiple corroborating findings escalate the score beyond
the worst individual finding (an attack *story* is worse than one alert).
"""
from __future__ import annotations

from app.core.schema import validate_severity

SEVERITY_WEIGHTS = {"info": 0, "low": 25, "medium": 50, "high": 75, "critical": 95}


def score_findings(findings: list[dict]) -> tuple[int, str, dict]:
    """Returns (score 0-100, overall severity level, severity distribution)."""
    distribution = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    if not findings:
        return 0, "info", distribution

    weighted = []
    for f in findings:
        sev = validate_severity(f.get("severity", "info"))
        distribution[sev] += 1
        confidence = max(0.0, min(1.0, float(f.get("confidence", 0.5))))
        weighted.append(SEVERITY_WEIGHTS[sev] * (0.5 + 0.5 * confidence))

    weighted.sort(reverse=True)
    score = weighted[0]
    # Corroboration bonus: each additional significant finding adds a decaying
    # fraction of its weight. Story > single alert.
    for i, w in enumerate(weighted[1:], start=1):
        score += w * (0.3 / i)

    score = int(round(min(100, score)))
    return score, level_for_score(score), distribution


def level_for_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"
