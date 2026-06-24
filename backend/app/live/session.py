"""Live-capture engine — PCAP replay + real device capture through the real
detection pipeline.

Replay: a bundled capture is released paced by its timestamps (time-compressed
to ~40s). Real capture: tcpdump grabs fixed windows off an interface. In both
cases the SAME network pre-processor + scoring used in file mode runs over the
buffered packets — detection never diverges between live and file analysis.

Per the chosen design the AI is invoked sparingly: in real-capture mode only
when a window is suspicious enough (sensitivity threshold), one call per window.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from app.modules.network import parser, preprocessor
from app.core.scoring import score_findings

try:
    from app.ai.analyzer import AUTHORITATIVE
except Exception:                       # pragma: no cover
    AUTHORITATIVE = {"known_bad_ip", "known_bad_domain", "malicious_ja3", "rule_match"}

_ALERT_LEVELS = {"medium", "high", "critical"}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TICK_SECONDS = 1.0
TARGET_REPLAY_SECONDS = 40.0

_REPO = Path(__file__).resolve().parents[3]
_DEMO = _REPO / "samples" / "demo"
SCENARIOS = {
    "c2_beacon": {"label": "C2 beaconing (njRAT-style)", "file": _DEMO / "demo_c2_beacon.pcap",
                  "blurb": "Periodic check-ins to a command-and-control host."},
    "port_scan": {"label": "Port scan / recon", "file": _DEMO / "demo_portscan.pcap",
                  "blurb": "Rapid probing of many ports on a host."},
    "dns_exfil": {"label": "DNS tunneling / exfiltration", "file": _DEMO / "demo_dns_exfil.pcap",
                  "blurb": "Data smuggled out inside DNS queries."},
}


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    return (ip.startswith(("10.", "192.168.", "127.", "169.254.", "::1", "fe80", "fc", "fd"))
            or any(ip.startswith(f"172.{i}.") for i in range(16, 32)))


def _endpoints(packets) -> set:
    """External endpoints (public IPs + domains) seen in a set of packets."""
    eps = set()
    for p in packets:
        if p.dst_ip and not _is_private(p.dst_ip):
            eps.add("ip:" + p.dst_ip)
        if getattr(p, "tls_sni", ""):
            eps.add("dom:" + p.tls_sni)
        for q in (getattr(p, "dns_queries", []) or []):
            eps.add("dom:" + q)
    return eps


def _traffic_breakdown(packets, top: int = 6):
    """Protocol mix + busiest external destinations, for the live traffic panel."""
    proto: dict[str, int] = {}
    talk: dict[str, int] = {}
    for p in packets:
        if getattr(p, "dns_queries", None):
            cat = "DNS"
        elif getattr(p, "tls_sni", "") or p.dst_port == 443 or p.src_port == 443:
            cat = "TLS"
        else:
            cat = p.protocol or "OTHER"
        proto[cat] = proto.get(cat, 0) + 1
        key = None
        if getattr(p, "tls_sni", ""):
            key = p.tls_sni
        elif getattr(p, "dns_queries", None):
            key = p.dns_queries[0]
        elif p.dst_ip and not _is_private(p.dst_ip):
            key = p.dst_ip
        if key:
            talk[key] = talk.get(key, 0) + 1
    talkers = sorted(talk.items(), key=lambda kv: -kv[1])[:top]
    return proto, [{"endpoint": k, "count": v} for k, v in talkers]


def _promote(observations) -> list[dict]:
    out = []
    for o in observations:
        out.append({
            "title": o.description or o.type.replace("_", " ").title(),
            "severity": o.severity_hint,
            "confidence": 1.0 if o.type in AUTHORITATIVE else 0.7,
            "mitre_techniques": list(getattr(o, "mitre_hints", []) or []),
        })
    return out


def _spawn_geo_refresher(session):
    """Best-effort background geo/reputation lookups so the live world-map can
    plot connections. Runs every ~8s off the session's current packets; never
    blocks the capture loop and silently no-ops when offline."""
    def loop():
        from app.modules.network import enrich
        while not session._stop.is_set():
            time.sleep(8)
            pkts = session.current_packets()
            if not pkts:
                continue
            try:
                summ = preprocessor.preprocess(pkts, "geo")
                summ = enrich.enrich(summ, max_ips=10)
                geo = summ.enrichment.get("ip_geolocation", {}) or {}
                rep = summ.enrichment.get("ip_reputation", {}) or {}
                with session._lock:
                    session.state["geo"] = geo
                    session.state["reputation"] = rep
            except Exception:
                pass
    threading.Thread(target=loop, daemon=True).start()


def _apply_watchlist(summary, user_id):
    try:
        from app.core import watchlist
        watchlist.apply(summary, user_id)
    except Exception:
        pass


def _build_case(packets, label, user_id):
    """Freeze captured packets into a full Report (reuses the file pipeline)."""
    from app.modules.network import enrich
    from app.pipeline import orchestrator
    summary = preprocessor.preprocess(packets, label)
    try:
        summary = enrich.enrich(summary, max_ips=12)
    except Exception:
        pass
    _apply_watchlist(summary, user_id)
    report = orchestrator.report_from_summary(summary, "network")
    return report.to_dict()


# ============================ replay session ===============================
class LiveSession:
    def __init__(self, user_id: str, scenario: str):
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario '{scenario}'")
        self.id = uuid.uuid4().hex[:12]
        self.user_id = user_id
        self.source = "replay"
        self.scenario = scenario
        self.label = SCENARIOS[scenario]["label"]
        path = SCENARIOS[scenario]["file"]
        self._packets = parser.parse_pcap(str(path))
        self._t0 = self._packets[0].ts if self._packets else 0.0
        span = (self._packets[-1].ts - self._t0) if len(self._packets) > 1 else 0.0
        self.speed = max(1.0, span / TARGET_REPLAY_SECONDS) if span > 0 else 1.0
        self._buffer: list = []
        self._idx = 0
        self._emit_times: deque = deque()
        self._alerts: list[dict] = []
        self._seen_alert_keys: set = set()
        self.score_history: list = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self.state = {
            "id": self.id, "source": "replay", "scenario": scenario, "label": self.label,
            "status": "starting", "packets_total": len(self._packets),
            "packets": 0, "pps": 0, "flows": 0, "elapsed": 0.0,
            "progress": 0, "score": 0, "severity": "info",
            "alerts": [], "score_history": [], "geo": {}, "reputation": {},
            "protocols": {}, "top_talkers": [],
            "speed": round(self.speed, 1),
        }

    def current_packets(self):
        with self._lock:
            return list(self._buffer)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        _spawn_geo_refresher(self)

    def stop(self):
        self._stop.set()

    def _run(self):
        start_wall = time.monotonic()
        last_tick = -TICK_SECONDS
        with self._lock:
            self.state["status"] = "running"
        n = len(self._packets)
        while not self._stop.is_set() and self._idx < n:
            elapsed = time.monotonic() - start_wall
            cap_time = elapsed * self.speed
            now = time.monotonic()
            while self._idx < n and (self._packets[self._idx].ts - self._t0) <= cap_time:
                self._buffer.append(self._packets[self._idx])
                self._emit_times.append(now)
                self._idx += 1
            if elapsed - last_tick >= TICK_SECONDS:
                last_tick = elapsed
                self._tick(elapsed)
            time.sleep(0.05)
        self._tick(time.monotonic() - start_wall, final=True)
        with self._lock:
            self.state["status"] = "stopped" if self._stop.is_set() else "finished"
            self.state["progress"] = 100

    def _tick(self, elapsed: float, final: bool = False):
        now = time.monotonic()
        while self._emit_times and now - self._emit_times[0] > 1.0:
            self._emit_times.popleft()
        pps = len(self._emit_times)
        flows = len({(p.src_ip, p.dst_ip, p.dst_port) for p in self._buffer})
        score, severity = 0, "info"
        if self._buffer:
            summary = preprocessor.preprocess(self._buffer, self.label)
            _apply_watchlist(summary, self.user_id)
            findings = _promote(summary.observations)
            score, severity, _ = score_findings(findings)
            for o in summary.observations:
                if o.severity_hint in _ALERT_LEVELS and o.id not in self._seen_alert_keys:
                    self._seen_alert_keys.add(o.id)
                    self._alerts.insert(0, {
                        "at": round(elapsed, 1), "type": o.type,
                        "severity": o.severity_hint, "description": o.description,
                        "mitre": list(getattr(o, "mitre_hints", []) or [])[:2],
                    })
        self.score_history.append([round(elapsed, 1), score])
        proto, talkers = _traffic_breakdown(self._buffer)
        with self._lock:
            self.state.update({
                "packets": self._idx, "pps": pps, "flows": flows,
                "elapsed": round(elapsed, 1),
                "progress": int(100 * self._idx / max(1, len(self._packets))),
                "score": score, "severity": severity,
                "alerts": list(self._alerts[:30]),
                "score_history": list(self.score_history[-120:]),
                "protocols": proto, "top_talkers": talkers,
            })

    def build_case(self):
        return _build_case(self.current_packets(), f"live-replay-{self.scenario}", self.user_id)

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self.state)


# ======================= real capture (this device) ========================
def _tcpdump_bin() -> str:
    return shutil.which("tcpdump") or "/usr/sbin/tcpdump"


def list_interfaces() -> list[dict]:
    try:
        out = subprocess.run([_tcpdump_bin(), "-D"], capture_output=True, text=True, timeout=6)
        ifs = []
        for line in out.stdout.splitlines():
            m = re.match(r"\s*\d+\.([^\s]+)\s*(.*)", line)
            if m:
                name = m.group(1)
                if name.startswith(("lo", "bluetooth", "p2p", "awdl")):
                    continue
                ifs.append({"name": name, "desc": m.group(2).strip()})
        return ifs
    except Exception:
        return []


def default_interface() -> str:
    import sys
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["route", "get", "default"], capture_output=True, text=True, timeout=4)
            m = re.search(r"interface:\s*(\S+)", out.stdout)
            if m:
                return m.group(1)
        else:
            out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=4)
            m = re.search(r"dev\s+(\S+)", out.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass
    for i in list_interfaces():
        if i["name"].startswith("en"):
            return i["name"]
    ifs = list_interfaces()
    return ifs[0]["name"] if ifs else "en0"


class RealCaptureSession:
    def __init__(self, user_id: str, interface: str = "", window: int = 30,
                 sensitivity: str = "medium"):
        self.id = uuid.uuid4().hex[:12]
        self.user_id = user_id
        self.source = "live"
        self.scenario = ""
        self.interface = interface or default_interface()
        self.window = max(5, int(window or 30))
        self.sensitivity = sensitivity if sensitivity in _SEV_RANK else "medium"
        self.baseline_windows = 2
        self._base_eps: set = set()
        self.windows: list[dict] = []
        self._alerts: list[dict] = []
        self._all_packets: list = []
        self.score_history: list = []
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._capture_fn = None
        self.label = f"live-{self.interface}"
        self.state = {
            "id": self.id, "source": "live", "interface": self.interface,
            "window": self.window, "sensitivity": self.sensitivity,
            "status": "starting", "error": None,
            "window_index": 0, "phase": "starting", "packets": 0, "flows": 0,
            "score": 0, "severity": "info", "ai_calls": 0,
            "usage": dict(self.usage), "windows": [], "alerts": [],
            "score_history": [], "geo": {}, "reputation": {},
            "protocols": {}, "top_talkers": [],
            "learning": True, "baseline_size": 0, "new_endpoints": 0,
        }

    def current_packets(self):
        with self._lock:
            return list(self._all_packets)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        _spawn_geo_refresher(self)

    def stop(self):
        self._stop.set()

    def _capture(self, path: str) -> tuple[bool, str]:
        if self._capture_fn:
            return self._capture_fn(path), ""
        cmd = [_tcpdump_bin(), "-i", self.interface, "-w", path, "-U", "-q", "-n"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except FileNotFoundError:
            return False, "tcpdump not found — install it (or Wireshark)."
        waited = 0.0
        while waited < self.window:
            if self._stop.is_set():
                break
            time.sleep(0.2)
            waited += 0.2
            if proc.poll() is not None:
                break
        proc.terminate()
        try:
            _, err = proc.communicate(timeout=5)
        except Exception:
            proc.kill(); err = b""
        msg = (err or b"").decode(errors="ignore")
        if "permission" in msg.lower() or "Operation not permitted" in msg:
            return False, "Permission denied — run the backend with sudo to capture."
        ok = os.path.exists(path) and os.path.getsize(path) > 24
        return ok, "" if ok else (msg.strip().splitlines()[-1] if msg.strip() else "No packets captured.")

    def _run(self):
        from app.ai import analyzer
        idx = 0
        while not self._stop.is_set():
            idx += 1
            with self._lock:
                self.state.update({"status": "running", "phase": "capturing", "window_index": idx})
            tmp = os.path.join(tempfile.gettempdir(), f"sai_live_{self.id}_{idx}.pcap")
            ok, err = self._capture(tmp)
            if self._stop.is_set():
                break
            if not ok:
                with self._lock:
                    self.state.update({"status": "error", "error": err, "phase": "idle"})
                return
            with self._lock:
                self.state["phase"] = "analyzing"
            try:
                packets = parser.parse_pcap(tmp)
            except Exception:
                packets = []
            finally:
                try: os.unlink(tmp)
                except OSError: pass

            summary = preprocessor.preprocess(packets, f"live-window-{idx}")
            _apply_watchlist(summary, self.user_id)
            obs = summary.observations

            # baseline / anomaly tracking
            eps = _endpoints(packets)
            learning = idx <= self.baseline_windows
            new_eps = [] if learning else [e for e in eps if e not in self._base_eps]
            self._base_eps |= eps

            findings, ai_used, note = [], False, ""
            if obs:
                max_rank = max(_SEV_RANK.get(o.severity_hint, 0) for o in obs)
                if max_rank >= _SEV_RANK[self.sensitivity]:
                    try:
                        res = analyzer.analyze(summary)
                        findings = res.get("findings", [])
                        note = (res.get("narrative", "") or "")[:160]
                        ai_used = res.get("ai_provider", "mock") != "mock" and not res.get("ai_degraded")
                        u = res.get("usage", {}) or {}
                        for k in self.usage:
                            self.usage[k] += u.get(k, 0)
                    except Exception:
                        findings = _promote(obs)
                else:
                    findings = _promote(obs)        # below sensitivity: deterministic, no AI
            score, severity, _ = score_findings(findings)

            flows = len({(p.src_ip, p.dst_ip, p.dst_port) for p in packets})
            wrec = {
                "index": idx, "packets": len(packets), "flows": flows,
                "observations": len(obs), "ai_used": ai_used,
                "score": score, "severity": severity,
                "top": [f.get("title", "") for f in findings[:3]],
                "note": note, "at": time.strftime("%H:%M:%S"),
                "learning": learning, "new_endpoints": len(new_eps),
            }
            for f in findings:
                if f.get("severity") in _ALERT_LEVELS:
                    self._alerts.insert(0, {
                        "at": wrec["at"], "window": idx,
                        "severity": f.get("severity"), "description": f.get("title", ""),
                        "mitre": list(f.get("mitre_techniques", []) or [])[:2],
                    })
            with self._lock:
                self._all_packets.extend(packets)
                self.windows.insert(0, wrec)
                self.score_history.append([idx, score])
                proto, talkers = _traffic_breakdown(self._all_packets)
                self.state.update({
                    "protocols": proto, "top_talkers": talkers,
                })
                self.state.update({
                    "phase": "capturing", "packets": len(packets), "flows": flows,
                    "score": score, "severity": severity,
                    "ai_calls": self.state["ai_calls"] + (1 if ai_used else 0),
                    "usage": dict(self.usage),
                    "windows": list(self.windows[:20]),
                    "alerts": list(self._alerts[:30]),
                    "score_history": list(self.score_history[-120:]),
                    "learning": learning, "baseline_size": len(self._base_eps),
                    "new_endpoints": len(new_eps),
                })
        with self._lock:
            self.state["status"] = "stopped"
            self.state["phase"] = "idle"

    def build_case(self):
        return _build_case(self.current_packets(), f"live-{self.interface}", self.user_id)

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self.state)


# ----------------------------- session manager -----------------------------
_SESSIONS: dict[str, object] = {}
_MGR_LOCK = threading.Lock()


def list_scenarios() -> list[dict]:
    return [{"id": k, "label": v["label"], "blurb": v["blurb"]} for k, v in SCENARIOS.items()]


def _register(sess) -> None:
    with _MGR_LOCK:
        for sid, s in list(_SESSIONS.items()):
            if getattr(s, "user_id", None) == sess.user_id:
                s.stop()
                _SESSIONS.pop(sid, None)
        _SESSIONS[sess.id] = sess
    sess.start()


def start_session(user_id: str, source: str = "replay", scenario: str = "",
                  interface: str = "", window: int = 30, sensitivity: str = "medium"):
    if source == "live":
        sess = RealCaptureSession(user_id, interface, window, sensitivity)
    else:
        sess = LiveSession(user_id, scenario)
    _register(sess)
    return sess


def get_session(session_id: str):
    with _MGR_LOCK:
        return _SESSIONS.get(session_id)


def stop_session(session_id: str) -> bool:
    with _MGR_LOCK:
        s = _SESSIONS.get(session_id)
    if s:
        s.stop()
        return True
    return False
