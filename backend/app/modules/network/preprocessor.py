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
        flow["dns"].extend(p.dns_queries)
    return flows


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

    # ---- Per-flow analysis -------------------------------------------------
    bytes_per_dst: dict[str, int] = defaultdict(int)
    for flow in flows.values():
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
                    summary.observations.append(new_obs(
                        type="beaconing",
                        description=(f"Host {flow['src']} contacts {dst}:{dport} every "
                                     f"~{mean:.0f}s with very regular timing ({len(flow_ts)} "
                                     "connections) — machine-like beaconing pattern"),
                        severity_hint="high",
                        data={"src": flow["src"], "dst": dst, "port": dport,
                              "interval_seconds": round(mean, 1), "jitter": round(stdev / mean, 3),
                              "connections": len(flow_ts)},
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

    # ---- Cross-flow analysis ----------------------------------------------
    # Port scan: one source touching many ports on one destination
    scan_map: dict[tuple, set] = defaultdict(set)
    for flow in flows.values():
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
