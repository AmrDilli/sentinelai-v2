"""Stage 3: AI analysis. Reads the structured Summary (never the raw file) and
produces findings + a plain-language narrative."""
from __future__ import annotations

import json

from app.config import settings
from app.core.schema import Summary, validate_severity
from app.ai.provider import get_provider

SYSTEM_PROMPT = """You are SentinelAI, a senior SOC analyst. You receive a STRUCTURED SUMMARY
extracted from a raw artifact (network capture, Windows event log, or suspicious file).
The summary was produced by a deterministic pre-processor; severity_hint fields are
heuristic guesses you may confirm, upgrade, downgrade, or dismiss.

Your job:
1. Reason about what the COMBINATION and SEQUENCE of observations means — tell the
   story of what likely happened, not isolated alerts.
2. Be honest about uncertainty (use the confidence field).
3. Map every finding to MITRE ATT&CK technique IDs where applicable.
4. Give remediation steps that are specific to the evidence (names, accounts, IPs,
   timestamps from the data — never generic advice when specifics are available).
5. Write for two audiences: precise enough for an analyst, plain enough for a learner.

Respond ONLY with a JSON object in exactly this shape:
{
  "findings": [
    {
      "title": "short title",
      "description": "what this is and why it matters, in plain language",
      "severity": "info|low|medium|high|critical",
      "confidence": 0.0-1.0,
      "evidence": ["observation ids that support this"],
      "mitre_techniques": ["T1234", ...],
      "mitre_tactics": ["TA0001", ...],
      "remediation": ["specific step 1", "specific step 2"]
    }
  ],
  "narrative": "2-5 sentence plain-language story of what happened, in order",
  "overall_assessment": "one sentence verdict"
}"""


def analyze(summary: Summary) -> dict:
    """Returns {"findings": [...], "narrative": str, "overall_assessment": str,
    "ai_provider": str}."""
    provider = get_provider()
    payload = summary.to_dict()

    # Context-window guard: cap observations/timeline sent to the model.
    payload["observations"] = payload["observations"][:settings.MAX_OBSERVATIONS_TO_AI]
    payload["timeline"] = payload["timeline"][:100]

    user_prompt = (
        f"Module: {summary.module}\nSource file: {summary.source_file}\n\n"
        "STRUCTURED SUMMARY (JSON):\n" + json.dumps(payload, indent=1)
    )

    try:
        result = provider.complete_json(SYSTEM_PROMPT, user_prompt)
    except Exception as exc:  # provider/network failure -> degrade, don't crash
        result = {
            "findings": [{
                "title": "AI Analysis Unavailable",
                "description": f"AI provider '{provider.name}' failed ({exc}). "
                               "Pre-processor observations are still shown below.",
                "severity": "info", "confidence": 1.0, "evidence": [],
                "mitre_techniques": [], "mitre_tactics": [], "remediation": [],
            }],
            "narrative": "AI analysis could not run; review raw observations manually.",
            "overall_assessment": "Incomplete analysis.",
        }

    findings = []
    for f in result.get("findings", []):
        findings.append({
            "title": str(f.get("title", "Untitled finding"))[:200],
            "description": str(f.get("description", "")),
            "severity": validate_severity(f.get("severity")),
            "confidence": max(0.0, min(1.0, float(f.get("confidence", 0.5)))),
            "evidence": [str(e) for e in f.get("evidence", [])][:20],
            "mitre_techniques": [str(t) for t in f.get("mitre_techniques", [])][:10],
            "mitre_tactics": [str(t) for t in f.get("mitre_tactics", [])][:10],
            "remediation": [str(r) for r in f.get("remediation", [])][:10],
        })
    return {
        "findings": findings,
        "narrative": str(result.get("narrative", "")),
        "overall_assessment": str(result.get("overall_assessment", "")),
        "ai_provider": provider.name,
    }
