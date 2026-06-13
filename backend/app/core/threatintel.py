"""Threat-intelligence feed: JA3 fingerprints + known-bad IPs and domains.

Design goals (same philosophy as the AI provider): works fully offline with a
bundled snapshot so the demo and CI need no network or keys, but can pull a
fresh feed from abuse.ch on demand when network is available.

  - Bundled data ships in app/data/threat_intel.json.
  - refresh_from_feeds() merges live abuse.ch indicators on top and caches the
    result to UPLOAD_DIR/threat_intel_cache.json so restarts keep the refresh.
  - Lookups (ja3_label / ip_label / domain_label) are O(1) dict hits and never
    touch the network, so they're safe to call from the hot pre-processing path.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from app.config import settings

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "threat_intel.json"
_CACHE_FILE = settings.UPLOAD_DIR / "threat_intel_cache.json"

# abuse.ch open feeds (no key required). Used only by refresh_from_feeds().
_JA3_FEED = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
_IP_FEED = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

_LOCK = threading.Lock()
_STATE = {
    "ja3": {}, "ips": {}, "domains": {},
    "source": "bundled", "version": "", "last_updated": None,
}


def _load_bundled() -> dict:
    try:
        return json.loads(_DATA_FILE.read_text())
    except Exception:
        return {"ja3": {}, "ips": {}, "domains": {}, "version": "unknown"}


def _load_cache() -> dict | None:
    try:
        if _CACHE_FILE.exists():
            return json.loads(_CACHE_FILE.read_text())
    except Exception:
        pass
    return None


def _init() -> None:
    """Populate state from bundled data, then overlay any cached refresh."""
    bundled = _load_bundled()
    with _LOCK:
        _STATE["ja3"] = dict(bundled.get("ja3", {}))
        _STATE["ips"] = dict(bundled.get("ips", {}))
        _STATE["domains"] = dict(bundled.get("domains", {}))
        _STATE["version"] = bundled.get("version", "")
        _STATE["source"] = "bundled"
        _STATE["last_updated"] = None
    cache = _load_cache()
    if cache:
        with _LOCK:
            _STATE["ja3"].update(cache.get("ja3", {}))
            _STATE["ips"].update(cache.get("ips", {}))
            _STATE["domains"].update(cache.get("domains", {}))
            _STATE["source"] = cache.get("source", "bundled+cache")
            _STATE["last_updated"] = cache.get("last_updated")


# ---- lookups (hot path, never hit the network) ------------------------------
def ja3_label(fingerprint: str) -> str | None:
    return _STATE["ja3"].get(fingerprint) if fingerprint else None


def ip_label(ip: str) -> str | None:
    return _STATE["ips"].get(ip) if ip else None


def domain_label(domain: str) -> str | None:
    """Match the domain or any parent domain (sub.evil.com -> evil.com)."""
    if not domain:
        return None
    parts = domain.lower().split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        hit = _STATE["domains"].get(candidate)
        if hit:
            return hit
    return None


def stats() -> dict:
    return {
        "source": _STATE["source"],
        "version": _STATE["version"],
        "last_updated": _STATE["last_updated"],
        "ja3": len(_STATE["ja3"]),
        "ips": len(_STATE["ips"]),
        "domains": len(_STATE["domains"]),
    }


# ---- optional live refresh from abuse.ch ------------------------------------
def refresh_from_feeds(timeout: int = 15) -> dict:
    """Pull fresh indicators from abuse.ch and merge them over the bundled set.
    Network-dependent and best-effort: failures leave the current state intact
    and surface as {"ok": False, "error": ...}. Returns updated stats on success."""
    import requests  # local import so the module loads without network libs ready

    new_ja3: dict[str, str] = {}
    new_ips: dict[str, str] = {}
    try:
        rj = requests.get(_JA3_FEED, timeout=timeout)
        rj.raise_for_status()
        for line in rj.text.splitlines():
            if not line or line.startswith("#"):
                continue
            cols = line.split(",")
            # CSV: ja3_md5,firstseen,listingreason
            if len(cols) >= 3 and len(cols[0]) == 32:
                new_ja3[cols[0].strip()] = cols[2].strip().strip('"') or "abuse.ch SSLBL"
    except Exception as exc:
        return {"ok": False, "error": f"JA3 feed: {exc}", **stats()}

    try:
        ri = requests.get(_IP_FEED, timeout=timeout)
        ri.raise_for_status()
        for line in ri.text.splitlines():
            if not line or line.startswith("#"):
                continue
            cols = line.split(",")
            # CSV: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
            if len(cols) >= 6 and cols[1].count(".") == 3:
                malware = cols[5].strip().strip('"') or "abuse.ch Feodo"
                new_ips[cols[1].strip()] = f"{malware} C2 (Feodo Tracker)"
    except Exception as exc:
        return {"ok": False, "error": f"IP feed: {exc}", **stats()}

    bundled = _load_bundled()
    merged = {
        "ja3": {**bundled.get("ja3", {}), **new_ja3},
        "ips": {**bundled.get("ips", {}), **new_ips},
        "domains": dict(bundled.get("domains", {})),
        "version": bundled.get("version", ""),
        "source": "bundled+abuse.ch",
        "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with _LOCK:
        _STATE.update({k: merged[k] for k in ("ja3", "ips", "domains", "source",
                                              "last_updated", "version")})
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(merged, indent=1))
    except Exception:
        pass  # cache write is best-effort; in-memory state is already updated
    return {"ok": True, **stats()}


_init()
