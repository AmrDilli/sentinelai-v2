"""Stage 3: AI analysis. Reads the structured Summary (never the raw file) and
produces findings + a plain-language narrative.

Quality features:
  - few-shot examples in the system prompt (steers format + reasoning style)
  - optional self-verification pass: the model critiques its own findings and
    removes false positives / fixes severities (AI_SELF_VERIFY=1)
  - response caching keyed on a hash of the summary (identical input -> no re-call)
  - per-analysis token + cost accounting surfaced in the report
"""
from __future__ import annotations

import hashlib
import json
import logging

from app.config import settings

logger = logging.getLogger("sentinelai.ai")
from app.core.schema import Summary, validate_severity
from app.ai.provider import get_provider

SYSTEM_PROMPT = """You are SentinelAI, a senior SOC analyst. You receive a STRUCTURED SUMMARY
extracted from a raw artifact (network capture, Windows event log, or suspicious file).
The summary was produced by a deterministic pre-processor; severity_hint fields are
heuristic guesses you may confirm, upgrade, downgrade, or DISMISS.

Your job:
1. Reason about what the COMBINATION and SEQUENCE of observations means — tell the
   story of what likely happened, not isolated alerts.
2. Actively reject false positives. Backup jobs look like exfiltration; vuln scanners
   look like attacks; admin maintenance looks like persistence. If benign is plausible,
   lower the severity and say so.
3. Be honest about uncertainty (use the confidence field).
4. Map every finding to MITRE ATT&CK technique IDs where applicable.
5. Give remediation steps SPECIFIC to the evidence (names, accounts, IPs, timestamps
   from the data — never generic advice when specifics are available).
6. Write for two audiences: precise for an analyst, plain enough for a learner.

Respond ONLY with a JSON object in exactly this shape:
{
  "findings": [
    {
      "title": "short title",
      "description": "what this is and why it matters, plain language",
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
}

EXAMPLE (forensics input -> good output):
Input observations: 8x failed logon for 'admin' from 45.133.1.99, then a successful
logon for 'admin' from the same IP, then account 'svc_backup' created and added to
Administrators, then Security log cleared.
Good output:
{
  "findings": [
    {"title": "Successful brute-force compromise of 'admin'",
     "description": "Eight failed logons followed by a success from the same external IP (45.133.1.99) indicate a password-guessing attack that succeeded.",
     "severity": "critical", "confidence": 0.9, "evidence": ["for-001"],
     "mitre_techniques": ["T1110", "T1078"], "mitre_tactics": ["TA0006"],
     "remediation": ["Disable 'admin' and force a password reset", "Block 45.133.1.99 at the perimeter", "Audit all actions by 'admin' after the success timestamp"]},
    {"title": "Persistence via new admin account + log clearing",
     "description": "Right after the compromise, 'svc_backup' was created and elevated, then the Security log was cleared — establishing persistence and covering tracks.",
     "severity": "critical", "confidence": 0.85, "evidence": ["for-002","for-003"],
     "mitre_techniques": ["T1136.001","T1098","T1070.001"], "mitre_tactics": ["TA0003","TA0005"],
     "remediation": ["Disable 'svc_backup'", "Re-enable and forward audit logging", "Hunt for the same pattern on peer hosts"]}
  ],
  "narrative": "An external host brute-forced the 'admin' account and logged in, then created and elevated 'svc_backup' for persistence before clearing the Security log to hide the activity.",
  "overall_assessment": "Confirmed account compromise with persistence and anti-forensics — treat as an active incident."
}"""

VERIFY_PROMPT = """You are a QA reviewer for SOC findings. Given the structured summary and a
draft set of findings, critically review them:
- Remove findings that are false positives or unsupported by the evidence.
- Downgrade severities that are overstated; upgrade ones that are understated given the
  combination of evidence.
- Fix or add MITRE technique IDs.
- Tighten confidence values to reflect real certainty.
Keep the SAME JSON schema (findings/narrative/overall_assessment). Return the corrected
object ONLY."""


def _cache_key(summary_dict: dict) -> str:
    # Drop volatile fields so identical analytical content hits the cache.
    stable = {k: v for k, v in summary_dict.items() if k != "generated_at"}
    payload = json.dumps(stable, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


_CACHE: dict[str, dict] = {}


def analyze(summary: Summary) -> dict:
    """Returns {findings, narrative, overall_assessment, ai_provider, usage, cached}."""
    provider = get_provider()
    payload = summary.to_dict()

    # Context-window guard: cap observations/timeline sent to the model.
    payload["observations"] = payload["observations"][:settings.MAX_OBSERVATIONS_TO_AI]
    payload["timeline"] = payload["timeline"][:100]

    key = f"{provider.name}:{_cache_key(payload)}"
    if settings.AI_CACHE and key in _CACHE:
        cached = dict(_CACHE[key])
        cached["cached"] = True
        return cached

    user_prompt = (
        f"Module: {summary.module}\nSource file: {summary.source_file}\n\n"
        "STRUCTURED SUMMARY (JSON):\n" + json.dumps(payload, indent=1)
    )

    usage_total = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0}

    def add_usage():
        for k in usage_total:
            usage_total[k] += provider.last_usage.get(k, 0)

    degraded = False
    try:
        result = provider.complete_json(SYSTEM_PROMPT, user_prompt)
        add_usage()

        # Optional self-verification pass (real providers only; skip for mock)
        if settings.AI_SELF_VERIFY and provider.name != "mock":
            verify_input = (
                "STRUCTURED SUMMARY:\n" + json.dumps(payload, indent=1)
                + "\n\nDRAFT FINDINGS:\n" + json.dumps(result, indent=1)
            )
            try:
                reviewed = provider.complete_json(VERIFY_PROMPT, verify_input)
                add_usage()
                if reviewed.get("findings") is not None:
                    result = reviewed
            except Exception:
                pass  # keep the draft if verification fails
    except Exception as exc:
        # The configured provider failed (bad/expired key, no credits, rate
        # limit, outage). Do NOT return an empty 0% result — for a security tool
        # that would make a malicious artifact look clean. Degrade to the
        # deterministic engine (promote pre-processor observations to findings)
        # so the score stays meaningful, and flag the run as degraded.
        from app.ai.provider import MockProvider
        degraded = True
        degraded_reason = str(exc)
        # Make the failure visible in the backend terminal (it was previously
        # only buried in the report text).
        logger.warning("AI provider '%s' failed — falling back to deterministic "
                       "analysis. Reason: %s", provider.name, degraded_reason)
        try:
            result = MockProvider().complete_json(SYSTEM_PROMPT, user_prompt)
        except Exception:
            return {
                "findings": [{
                    "title": "Analysis Engine Unavailable",
                    "description": f"AI provider '{provider.name}' failed "
                                   f"({degraded_reason}) and the deterministic "
                                   "fallback also failed. Review raw observations manually.",
                    "severity": "info", "confidence": 1.0, "evidence": [],
                    "mitre_techniques": [], "mitre_tactics": [], "remediation": [],
                }],
                "narrative": "Analysis could not run; review raw observations manually.",
                "overall_assessment": "Incomplete analysis.",
                "ai_provider": provider.name, "usage": usage_total,
                "cached": False, "ai_degraded": True,
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

    narrative = str(result.get("narrative", ""))
    if degraded:
        narrative = (f"[DEGRADED MODE — the '{provider.name}' AI provider was "
                     f"unavailable ({degraded_reason}); showing deterministic "
                     "rule-based analysis. Findings and score are valid but lack "
                     "AI reasoning. Fix the provider/API key for full analysis.] "
                     + narrative)

    out = {
        "findings": findings,
        "narrative": narrative,
        "overall_assessment": str(result.get("overall_assessment", "")),
        "ai_provider": provider.name + (" (degraded)" if degraded else ""),
        "usage": usage_total,
        "cached": False,
        "ai_degraded": degraded,
    }
    # Don't cache a degraded result — re-run for real once the provider recovers.
    if settings.AI_CACHE and not degraded:
        _CACHE[key] = out
    return out
