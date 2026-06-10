"""Tiered automated response (SOAR).

Tier policy (by overall score):
  low      -> notify only
  medium   -> suggest actions, wait for analyst approval
  high+    -> mark actions for immediate (simulated) execution

Actions are generated from finding types and IOCs. Execution here is
simulated/logged — wiring real EDR/firewall APIs is an integration exercise,
the tier logic and audit trail are the point.
"""
from __future__ import annotations

from app.config import settings

TIER_NOTIFY, TIER_APPROVAL, TIER_AUTO = "notify", "require_approval", "auto_execute"


def tier_for_score(score: int) -> str:
    if score >= settings.SOAR_AUTO_THRESHOLD:
        return TIER_AUTO
    if score >= settings.SOAR_APPROVAL_THRESHOLD:
        return TIER_APPROVAL
    return TIER_NOTIFY


def generate_actions(findings: list[dict], iocs: dict, score: int) -> list[dict]:
    tier = tier_for_score(score)
    actions: list[dict] = []

    def add(action: str, target: str, reason: str):
        actions.append({
            "action": action,
            "target": target,
            "reason": reason,
            "tier": tier,
            "status": "executed (simulated)" if tier == TIER_AUTO else
                      "pending approval" if tier == TIER_APPROVAL else "notification sent",
        })

    severities = {f.get("severity") for f in findings}
    titles = " ".join(f.get("title", "").lower() for f in findings)

    for ip in (iocs.get("ips") or [])[:10]:
        add("block_ip", ip, "IOC identified during analysis")
    for domain in (iocs.get("domains") or [])[:10]:
        add("sinkhole_domain", domain, "Suspicious domain contacted")
    for h in (iocs.get("hashes") or [])[:5]:
        add("quarantine_hash", h, "Malicious/suspicious file hash")
    for account in (iocs.get("accounts") or [])[:10]:
        add("disable_account_and_reset_credentials", account, "Account implicated in incident")

    if "credential" in titles or "brute" in titles or "login" in titles:
        add("force_password_reset", "affected accounts", "Credential attack indicators present")
    if "exfiltration" in titles or "beacon" in titles or "c2" in titles:
        add("isolate_host", "affected host", "Possible active C2/exfiltration channel")
    if {"high", "critical"} & severities and not actions:
        add("isolate_host", "affected host", "High-severity findings with no scoped IOC")

    if not actions:
        add("notify_analyst", "SOC queue", "Low-risk findings recorded for review")
    return actions
