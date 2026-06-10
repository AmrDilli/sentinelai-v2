"""Threat-intel enrichment for the network module.

AbuseIPDB reputation + free-tier geolocation (ip-api.com). Both are optional:
without keys/network, enrichment is skipped and the pipeline still works.
Results land in summary.enrichment so the AI can weigh reputation context.
"""
from __future__ import annotations

import requests

from app.config import settings
from app.core.schema import Summary, Observation


def enrich(summary: Summary, max_ips: int = 15) -> Summary:
    ips = (summary.iocs.ips or [])[:max_ips]
    if not ips:
        return summary

    reputation, geo = {}, {}
    for ip in ips:
        rep = _abuseipdb(ip)
        if rep:
            reputation[ip] = rep
        loc = _geolocate(ip)
        if loc:
            geo[ip] = loc

    summary.enrichment["ip_reputation"] = reputation
    summary.enrichment["ip_geolocation"] = geo

    for ip, rep in reputation.items():
        if rep.get("abuse_confidence", 0) >= 50:
            summary.observations.append(Observation(
                id=f"net-rep-{ip.replace('.', '-').replace(':', '-')}",
                type="malicious_ip",
                description=(f"{ip} is flagged by AbuseIPDB with "
                             f"{rep['abuse_confidence']}% abuse confidence "
                             f"({rep.get('total_reports', 0)} reports, "
                             f"country: {geo.get(ip, {}).get('country', 'unknown')})"),
                severity_hint="high",
                data={"ip": ip, **rep},
                mitre_hints=["T1071"],
            ))
    return summary


def _abuseipdb(ip: str) -> dict | None:
    if not settings.ABUSEIPDB_API_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=10,
        )
        d = r.json().get("data", {})
        return {
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "isp": d.get("isp", ""),
            "usage_type": d.get("usageType", ""),
        }
    except requests.RequestException:
        return None


def _geolocate(ip: str) -> dict | None:
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon,org"},
            timeout=10,
        )
        d = r.json()
        if d.get("status") != "success":
            return None
        return {"country": d.get("country"), "city": d.get("city"),
                "lat": d.get("lat"), "lon": d.get("lon"), "org": d.get("org")}
    except requests.RequestException:
        return None
