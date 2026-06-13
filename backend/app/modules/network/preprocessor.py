"""Stage 2 (Network): packets -> standard Summary.

Reconstructs flows, computes entropy, detects beaconing, port scans,
plaintext-credential protocols, non-standard ports, DNS anomalies, and
baseline deviation — then emits the compact Summary the AI reasons over.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone

from app.core.schema import Summary, Observation, TimelineEvent, IOCs
from app.modules.network.parser import Packet

WELL_KNOWN = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 25: "SMTP", 21: "FTP",
              23: "Telnet", 3389: "RDP", 445: "SMB", 139: "NetBIOS", 3306: "MySQL",
              5432: "PostgreSQL", 8080: "HTTP-alt", 123: "NTP", 110: "POP3", 143: "IMAP"}

PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.2", "172.30.", "172.31.", "127.", "169.254.")

# A tiny illustrative JA3 blocklist. In production this is fed from a threat-intel
# feed (e.g. abuse.ch JA3 fingerprints); kept small here for the demo.
KNOWN_BAD_JA3 = {
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (default profile)",
    "72a589da586844d7f0818ce684948eea": "Metasploit Meterpreter",
    "e7d705a3286e19ea42f587b344ee6865": "Tor client",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def is_private(ip: str) -> bool:
    return ip.startswith(PRIVATE_PREFIXES) or ":" in ip and ip.startswith("fe80")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def build_flows(packets: list[Packet]) -> dict[tuple, dict]:
    """Group packets into bidirectional 5-tuple flows (TCP stream reassembly:
    payloads concatenated in time order per direction)."""
    flows: dict[tuple, dict] = {}
    for p in packets:
        if p.protocol not in ("TCP", "UDP"):
            continue
        fwd = (p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.protocol)
        rev = (p.dst_ip, p.dst_port, p.src_ip, p.src_port, p.protocol)
        key = fwd if fwd in flows else rev if rev in flows else fwd
        flow = flows.setdefault(key, {
            "src": key[0], "sport": key[1], "dst": key[2], "dport": key[3],
            "proto": key[4], "packets": 0, "bytes": 0, "payload": b"",
            "timestamps": [], "sni": "", "tls_version": "", "dns": [],
            "ja3": "", "http_requests": [],
        })
        flow["packets"] += 1
        flow["bytes"] += p.length
        flow["timestamps"].append(p.ts)
        if len(flow["payload"]) < 65536:
            flow["payload"] += p.payload
        if p.tls_sni:
            flow["sni"] = p.tls_sni
        if p.tls_version:
            flow["tls_version"] = p.tls_version
        if p.ja3:
            flow["ja3"] = p.ja3
        if p.http:
            flow["http_requests"].append(p.http)
        flow["dns"].extend(p.dns_queries)
    return flows


def merge_channels(flows: dict[tuple, dict]) -> dict[tuple, dict]:
    """Collapse repeated connections to the same (client, server, port, proto)
    into one logical channel.

    A beaconing host opens a fresh TCP connection (new ephemeral source port)
    on every callback, so each becomes a separate 5-tuple flow. Analysing those
    flows individually both (a) emits one near-identical observation per
    reconnection — noise the AI then has to wade through — and (b) can hide
    beaconing, because no single short-lived flow has enough samples to measure
    timing. Merging by destination channel fixes both: detectors see the full
    picture once, and reconnection timestamps line up into the real beacon."""
    channels: dict[tuple, dict] = {}
    for f in flows.values():
        key = (f["src"], f["dst"], f["dport"], f["proto"])
        c = channels.get(key)
        if c is None:
            c = channels[key] = {
                "src": f["src"], "sport": f["sport"], "dst": f["dst"],
                "dport": f["dport"], "proto": f["proto"], "packets": 0,
                "bytes": 0, "payload": b"", "timestamps": [], "sni": "",
                "tls_version": "", "dns": [], "ja3": "", "http_requests": [],
                "connections": 0,
            }
        c["packets"] += f["packets"]
        c["bytes"] += f["bytes"]
        c["timestamps"].extend(f["timestamps"])
        if len(c["payload"]) < 65536:
            c["payload"] += f["payload"][:65536 - len(c["payload"])]
        c["sni"] = c["sni"] or f["sni"]
        c["tls_version"] = c["tls_version"] or f["tls_version"]
        c["ja3"] = c["ja3"] or f["ja3"]
        c["http_requests"].extend(f["http_requests"])
        c["dns"].extend(f["dns"])
        c["connections"] += 1
    return channels


def preprocess(packets: list[Packet], source_file: str) -> Summary:
    summary = Summary(module="network", source_file=source_file)
    obs_counter = 0

    def new_obs(**kwargs) -> Observation:
        nonlocal obs_counter
        obs_counter += 1
        return Observation(id=f"net-{obs_counter:03d}", **kwargs)

    if not packets:
        summary.stats = {"packets": 0}
        return summary

    flows = build_flows(packets)
    channels = merge_channels(flows)
    proto_counts = Counter(p.protocol for p in packets)
    times = [p.ts for p in packets]
    duration = max(times) - min(times) if len(times) > 1 else 0

    external_ips = sorted({
        ip for p in packets for ip in (p.src_ip, p.dst_ip) if ip and not is_private(ip)
    })
    all_dns = [q for p in packets for q in p.dns_queries]

    summary.stats = {
        "packets": len(packets),
        "flows": len(flows),
        "duration_seconds": round(duration, 2),
        "protocol_breakdown": dict(proto_counts),
        "unique_external_ips": len(external_ips),
        "unique_dns_queries": len(set(all_dns)),
        "total_bytes": sum(p.length for p in packets),
        "capture_start": _iso(min(times)),
        "capture_end": _iso(max(times)),
    }
    summary.iocs = IOCs(ips=external_ips[:50], domains=sorted(set(all_dns))[:50])

    # ---- Per-channel analysis ----------------------------------------------
    # Iterate merged channels (reconnections to the same host:port collapsed)
    # so each detector fires once per destination, not once per TCP connection.
    bytes_per_dst: dict[str, int] = defaultdict(int)
    for flow in channels.values():
        dst, dport, proto = flow["dst"], flow["dport"], flow["proto"]
        payload_entropy = shannon_entropy(flow["payload"][:8192])
        bytes_per_dst[dst] += flow["bytes"]
        flow_ts = sorted(flow["timestamps"])

        # Beaconing: regular intervals to an external host
        if not is_private(dst) and len(flow_ts) >= 6:
            intervals = [b - a for a, b in zip(flow_ts, flow_ts[1:]) if b - a > 0.5]
            if len(intervals) >= 5:
                mean = sum(intervals) / len(intervals)
                stdev = (sum((x - mean) ** 2 for x in intervals) / len(intervals)) ** 0.5
                if mean > 1 and stdev / mean < 0.25:  # low jitter = machine-like
                    callbacks = flow.get("connections", len(flow_ts))
                    summary.observations.append(new_obs(
                        type="beaconing",
                        description=(f"Host {flow['src']} contacts {dst}:{dport} every "
                                     f"~{mean:.0f}s with very regular timing ({callbacks} "
                                     "connections) — machine-like beaconing pattern"),
                        severity_hint="high",
                        data={"src": flow["src"], "dst": dst, "port": dport,
                              "interval_seconds": round(mean, 1), "jitter": round(stdev / mean, 3),
                              "connections": callbacks},
                        timestamps=[_iso(flow_ts[0]), _iso(flow_ts[-1])],
                        mitre_hints=["T1071", "T1573"],
                    ))

        # High-entropy payload on a non-TLS port (possible custom encryption)
        if payload_entropy > 7.2 and dport not in (443, 22) and len(flow["payload"]) > 512:
            summary.observations.append(new_obs(
                type="high_entropy_traffic",
                description=(f"Flow {flow['src']} -> {dst}:{dport} carries high-entropy "
                             f"payload (entropy {payload_entropy:.2f}/8.0) on a port not "
                             "normally encrypted — possible custom encryption or tunneled data"),
                severity_hint="medium",
                data={"src": flow["src"], "dst": dst, "port": dport,
                      "entropy": round(payload_entropy, 2), "bytes": flow["bytes"]},
                mitre_hints=["T1573", "T1048"],
            ))

        # Non-standard port for known service / unknown high port to external IP
        if not is_private(dst) and dport not in WELL_KNOWN and dport > 1024 and flow["bytes"] > 10000:
            summary.observations.append(new_obs(
                type="nonstandard_port",
                description=(f"Significant traffic ({flow['bytes']} bytes) from {flow['src']} "
                             f"to external host {dst} on uncommon port {dport}"),
                severity_hint="low",
                data={"src": flow["src"], "dst": dst, "port": dport, "bytes": flow["bytes"]},
                mitre_hints=["T1571"],
            ))

        # Plaintext credential-prone protocols
        if dport in (23, 21, 110) and flow["packets"] > 3:
            summary.observations.append(new_obs(
                type="plaintext_protocol",
                description=(f"{WELL_KNOWN[dport]} (plaintext credentials) session "
                             f"{flow['src']} -> {dst}"),
                severity_hint="low",
                data={"src": flow["src"], "dst": dst, "protocol": WELL_KNOWN[dport]},
            ))

        # TLS details
        if flow["tls_version"]:
            if flow["tls_version"] in ("TLS 1.0", "TLS 1.1"):
                summary.observations.append(new_obs(
                    type="legacy_tls",
                    description=(f"Deprecated {flow['tls_version']} handshake to "
                                 f"{flow['sni'] or dst}:{dport}"),
                    severity_hint="low",
                    data={"dst": dst, "sni": flow["sni"], "version": flow["tls_version"]},
                ))
            if flow["sni"] and flow["sni"] not in summary.iocs.domains:
                summary.iocs.domains.append(flow["sni"])

        # JA3 fingerprint of known-malicious tooling
        if flow["ja3"]:
            label = KNOWN_BAD_JA3.get(flow["ja3"])
            if label:
                summary.observations.append(new_obs(
                    type="malicious_ja3",
                    description=(f"TLS client fingerprint (JA3 {flow['ja3']}) matches "
                                 f"known tooling: {label} — to {flow['sni'] or dst}:{dport}"),
                    severity_hint="high",
                    data={"ja3": flow["ja3"], "tool": label, "dst": dst, "sni": flow["sni"]},
                    mitre_hints=["T1573"],
                ))

        # HTTP request inspection — dedup identical requests first (a beaconing
        # channel repeats the same GET on every callback; report it once).
        seen_reqs: set[tuple] = set()
        unique_reqs = []
        for req in flow["http_requests"]:
            sig = (req.get("method"), req.get("host"), req.get("uri"), req.get("user_agent"))
            if sig not in seen_reqs:
                seen_reqs.add(sig)
                unique_reqs.append(req)
        for req in unique_reqs[:5]:
            host, uri, ua = req.get("host", ""), req.get("uri", ""), req.get("user_agent", "")
            if host:
                full = f"http://{host}{uri}"
                if full not in summary.iocs.urls:
                    summary.iocs.urls.append(full)
                if host not in summary.iocs.domains:
                    summary.iocs.domains.append(host)
            # Suspicious user agents (empty, or known offensive tools)
            ua_low = ua.lower()
            if not ua and host:
                summary.observations.append(new_obs(
                    type="suspicious_http",
                    description=f"HTTP {req.get('method')} to {host}{uri} with NO User-Agent "
                                "— uncommon for browsers, typical of scripts/malware",
                    severity_hint="low",
                    data=req, mitre_hints=["T1071.001"],
                ))
            elif any(t in ua_low for t in ("sqlmap", "nikto", "curl", "python-requests",
                                           "powershell", "wget", "metasploit", "nmap")):
                summary.observations.append(new_obs(
                    type="tooling_user_agent",
                    description=f"HTTP request to {host}{uri} uses tool/script User-Agent '{ua}'",
                    severity_hint="medium",
                    data=req, mitre_hints=["T1071.001"],
                ))

    # ---- Cross-flow analysis ----------------------------------------------
    # Port scan: one source touching many ports on one destination
    scan_map: dict[tuple, set] = defaultdict(set)
    for flow in channels.values():
        if flow["proto"] == "TCP":
            scan_map[(flow["src"], flow["dst"])].add(flow["dport"])
    for (src, dst), ports in scan_map.items():
        if len(ports) >= 15:
            summary.observations.append(new_obs(
                type="port_scan",
                description=f"{src} probed {len(ports)} distinct TCP ports on {dst} — port scan",
                severity_hint="medium",
                data={"src": src, "dst": dst, "ports_touched": len(ports)},
                mitre_hints=["T1046"],
            ))

    # DNS anomalies: long/random-looking names (DGA), excessive TXT-length queries
    for name in set(all_dns):
        label = name.split(".")[0]
        if len(label) > 30 or (len(label) > 14 and shannon_entropy(label.encode()) > 3.7):
            summary.observations.append(new_obs(
                type="suspicious_dns",
                description=(f"DNS query for '{name}' has a long/high-entropy label — "
                             "possible DGA domain or DNS tunneling"),
                severity_hint="medium",
                data={"query": name, "label_entropy": round(shannon_entropy(label.encode()), 2)},
                mitre_hints=["T1568.002", "T1071.004"],
            ))

    # DNS tunneling: many distinct subdomains under one parent domain with long,
    # high-entropy labels = data smuggled inside DNS queries. Scored on volume.
    by_parent: dict[str, list[str]] = defaultdict(list)
    for name in all_dns:
        parts = name.split(".")
        if len(parts) >= 2:
            by_parent[".".join(parts[-2:])].append(parts[0])
    for parent, labels in by_parent.items():
        unique = set(labels)
        if len(unique) < 20:
            continue
        avg_len = sum(len(l) for l in unique) / len(unique)
        avg_entropy = sum(shannon_entropy(l.encode()) for l in unique) / len(unique)
        # tunneling score 0-100 from subdomain count + label length + entropy
        score = min(100, len(unique) // 2 + (avg_len > 20) * 25 + (avg_entropy > 3.5) * 25)
        if score >= 50:
            summary.observations.append(new_obs(
                type="dns_tunneling",
                description=(f"{len(unique)} unique subdomains queried under '{parent}' "
                             f"(avg label {avg_len:.0f} chars, entropy {avg_entropy:.1f}) — "
                             f"strong DNS tunneling / exfiltration indicator (score {score}/100)"),
                severity_hint="high" if score >= 70 else "medium",
                data={"parent_domain": parent, "unique_subdomains": len(unique),
                      "avg_label_length": round(avg_len, 1),
                      "avg_label_entropy": round(avg_entropy, 2), "tunneling_score": score},
                mitre_hints=["T1071.004", "T1048"],
            ))

    # Baseline deviation: any external destination receiving an outsized share of bytes
    ext_bytes = {ip: b for ip, b in bytes_per_dst.items() if not is_private(ip)}
    if len(ext_bytes) >= 3:
        total = sum(ext_bytes.values())
        for ip, b in ext_bytes.items():
            if total > 0 and b / total > 0.6 and b > 100_000:
                summary.observations.append(new_obs(
                    type="volume_anomaly",
                    description=(f"External host {ip} received {b:,} bytes — "
                                 f"{100*b/total:.0f}% of all outbound external traffic; "
                                 "large deviation from an even baseline"),
                    severity_hint="medium",
                    data={"dst": ip, "bytes": b, "share": round(b / total, 2)},
                    mitre_hints=["T1041"],
                ))

    # ---- Timeline -----------------------------------------------------------
    summary.timeline.append(TimelineEvent(
        timestamp=summary.stats["capture_start"], event="Capture start",
        detail=f"{len(packets)} packets over {duration:.0f}s"))
    for obs in summary.observations:
        if obs.timestamps:
            summary.timeline.append(TimelineEvent(
                timestamp=obs.timestamps[0], event=obs.type,
                detail=obs.description, severity=obs.severity_hint))
    summary.timeline.append(TimelineEvent(
        timestamp=summary.stats["capture_end"], event="Capture end"))
    summary.timeline.sort(key=lambda t: t.timestamp)
    return summary
