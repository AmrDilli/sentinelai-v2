"""AI provider abstraction.

One interface, three implementations:
  DeepSeekProvider — OpenAI-compatible chat completions (dev/testing, cheap)
  ClaudeProvider   — Anthropic Messages API (production)
  MockProvider     — deterministic, offline; turns severity hints into findings
                     so the entire pipeline runs with no API key (demos, tests, CI)

Switching providers is one env var: AI_PROVIDER=deepseek|claude|mock

Each provider records token usage + an estimated USD cost for the last call on
`self.last_usage`, so the pipeline can report cost per analysis.
"""
from __future__ import annotations

import json
import re

import requests

from app.config import settings

# Approximate USD per 1K tokens (input, output). Update as pricing changes.
PRICING = {
    "deepseek": (0.00027, 0.0011),
    "claude": (0.003, 0.015),
    "mock": (0.0, 0.0),
}


class AIProvider:
    name = "base"

    def __init__(self):
        self.last_usage = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0}

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError

    def complete_json(self, system: str, user: str) -> dict:
        """Call the model and parse a JSON object out of the reply."""
        text = self.complete(system, user)
        return extract_json(text)

    def _record(self, prompt_tokens: int, completion_tokens: int):
        pin, pout = PRICING.get(self.name, (0.0, 0.0))
        self.last_usage = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cost_usd": round(prompt_tokens / 1000 * pin + completion_tokens / 1000 * pout, 6),
        }


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


def _estimate_tokens(*texts: str) -> int:
    """Rough fallback when the API doesn't return usage (~4 chars/token)."""
    return sum(len(t) for t in texts) // 4


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
                "response_format": {"type": "json_object"},
            },
            timeout=120,
        )
        if not r.ok:
            # Surface DeepSeek's actual error body (e.g. "Model Not Exist",
            # "Insufficient Balance", rate limit) instead of a generic HTTP error.
            raise RuntimeError(f"DeepSeek API {r.status_code} at "
                               f"{settings.DEEPSEEK_BASE_URL} (model "
                               f"'{settings.DEEPSEEK_MODEL}'): {r.text[:400]}")
        body = r.json()
        usage = body.get("usage", {})
        text = body["choices"][0]["message"]["content"]
        self._record(usage.get("prompt_tokens") or _estimate_tokens(system, user),
                     usage.get("completion_tokens") or _estimate_tokens(text))
        return text


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
        if not r.ok:
            raise RuntimeError(f"Anthropic API {r.status_code} (model "
                               f"'{settings.CLAUDE_MODEL}'): {r.text[:400]}")
        body = r.json()
        usage = body.get("usage", {})
        text = body["content"][0]["text"]
        self._record(usage.get("input_tokens") or _estimate_tokens(system, user),
                     usage.get("output_tokens") or _estimate_tokens(text))
        return text


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
        self._record(0, 0)
        return json.dumps({"findings": findings, "narrative": narrative,
                           "overall_assessment": "See findings."})


def get_provider() -> AIProvider:
    provider = settings.AI_PROVIDER.lower()
    if provider == "deepseek" and settings.DEEPSEEK_API_KEY:
        return DeepSeekProvider()
    if provider == "claude" and settings.ANTHROPIC_API_KEY:
        return ClaudeProvider()
    return MockProvider()
