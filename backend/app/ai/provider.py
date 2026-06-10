"""AI provider abstraction.

One interface, three implementations:
  DeepSeekProvider — OpenAI-compatible chat completions (dev/testing, cheap)
  ClaudeProvider   — Anthropic Messages API (production)
  MockProvider     — deterministic, offline; turns severity hints into findings
                     so the entire pipeline runs with no API key (demos, tests, CI)

Switching providers is one env var: AI_PROVIDER=deepseek|claude|mock
"""
from __future__ import annotations

import json
import re

import requests

from app.config import settings


class AIProvider:
    name = "base"

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError

    def complete_json(self, system: str, user: str) -> dict:
        """Call the model and parse a JSON object out of the reply."""
        text = self.complete(system, user)
        return extract_json(text)


def extract_json(text: str) -> dict:
    """Models sometimes wrap JSON in markdown fences or prose — extract robustly."""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # last resort: outermost braces
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start:end + 1])
        raise


class DeepSeekProvider(AIProvider):
    name = "deepseek"

    def complete(self, system: str, user: str) -> str:
        r = requests.post(
            f"{settings.DEEPSEEK_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {settings.DEEPSEEK_API_KEY}"},
            json={
                "model": settings.DEEPSEEK_MODEL,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}],
                "temperature": 0.2,
                "max_tokens": 4096,
            },
            timeout=120,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


class ClaudeProvider(AIProvider):
    name = "claude"

    def complete(self, system: str, user: str) -> str:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": settings.CLAUDE_MODEL,
                "system": system,
                "messages": [{"role": "user", "content": user}],
                "max_tokens": 4096,
            },
            timeout=120,
        )
        r.raise_for_status()
        return r.json()["content"][0]["text"]


class MockProvider(AIProvider):
    """Deterministic offline provider. Promotes pre-processor observations into
    findings and writes a template narrative. Lets the full pipeline, API, and
    dashboard run with zero API keys — and makes tests reproducible."""
    name = "mock"

    def complete(self, system: str, user: str) -> str:
        summary = extract_json(user) if "{" in user else {}
        observations = summary.get("observations", [])
        findings = []
        for obs in observations:
            sev = obs.get("severity_hint", "info")
            if sev == "info":
                continue
            findings.append({
                "title": obs.get("type", "finding").replace("_", " ").title(),
                "description": obs.get("description", ""),
                "severity": sev,
                "confidence": 0.75,
                "evidence": [obs.get("id", "")],
                "mitre_techniques": obs.get("mitre_hints", []),
                "mitre_tactics": [],
                "remediation": [
                    "Review the referenced evidence and confirm the activity is unauthorized.",
                    "Scope affected hosts/accounts before remediating.",
                ],
            })
        if not findings:
            findings.append({
                "title": "No Significant Threats Identified",
                "description": "Pre-processing surfaced no suspicious observations.",
                "severity": "info", "confidence": 0.6, "evidence": [],
                "mitre_techniques": [], "mitre_tactics": [], "remediation": [],
            })
        narrative = (
            f"[Mock analysis — set AI_PROVIDER=deepseek or claude for real reasoning] "
            f"Analyzed {summary.get('module', 'unknown')} summary of "
            f"'{summary.get('source_file', '?')}': {len(observations)} observations, "
            f"{len(findings)} promoted to findings."
        )
        return json.dumps({"findings": findings, "narrative": narrative,
                           "overall_assessment": "See findings."})


def get_provider() -> AIProvider:
    provider = settings.AI_PROVIDER.lower()
    if provider == "deepseek" and settings.DEEPSEEK_API_KEY:
        return DeepSeekProvider()
    if provider == "claude" and settings.ANTHROPIC_API_KEY:
        return ClaudeProvider()
    return MockProvider()
