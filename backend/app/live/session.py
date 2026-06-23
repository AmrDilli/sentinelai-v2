"""Live-capture engine (MVP) — PCAP replay through the real detection pipeline.

A capture is preloaded and its packets are released paced by their original
timestamps (time-compressed so a long capture replays in ~40s). Every tick the
*same* network pre-processor used in file mode runs over the buffer accumulated
so far, observations are promoted to deterministic findings, and a 0-100 risk
score is computed. The session exposes a JSON `state` snapshot that the
WebSocket endpoint streams to the browser.

Design note: detection logic is NOT duplicated here — we reuse
`network.preprocessor.preprocess` and `core.scoring.score_findings`, so live
and file analysis always agree. The AI is intentionally not called in the MVP
(deterministic engine only); throttled live AI is a later milestone.
"""
from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from pathlib import Path

from app.modules.network import parser, preprocessor
from app.core.scoring import score_findings

# Detections that are deterministic + high confidence (mirror analyzer.AUTHORITATIVE).
try:
    from app.ai.analyzer import AUTHORITATIVE
except Exception:                       # pragma: no cover
    AUTHORITATIVE = {"known_bad_ip", "known_bad_domain", "malicious_ja3", "rule_match"}

_ALERT_LEVELS = {"medium", "high", "critical"}
TICK_SECONDS = 1.0                      # how often we re-analyse + push state
TARGET_REPLAY_SECONDS = 40.0            # compress any capture to ~this long

_REPO = Path(__file__).resolve().parents[3]
SCENARIOS = {
    "c2_beacon": {
        "label": "C2 beaconing (njRAT-style)",
        "file": _REPO / "samples" / "demo" / "demo_c2_beacon.pcap",
        "blurb": "Periodic check-ins to a command-and-control host.",
    },
}


def _promote(observations) -> list[dict]:
    """Observations -> deterministic findings (same idea as the mock provider),
    so the live risk score matches what the file pipeline produces offline."""
    out = []
    for o in observations:
        out.append({
            "title": o.description or o.type.replace("_", " ").title(),
            "severity": o.severity_hint,
            "confidence": 1.0 if o.type in AUTHORITATIVE else 0.7,
            "mitre_techniques": list(getattr(o, "mitre_hints", []) or []),
        })
    return out


class LiveSession:
    def __init__(self, user_id: str, scenario: str):
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario '{scenario}'")
        self.id = uuid.uuid4().hex[:12]
        self.user_id = user_id
        self.scenario = scenario
        self.label = SCENARIOS[scenario]["label"]
        path = SCENARIOS[scenario]["file"]
        self._packets = parser.parse_pcap(str(path))
        self._t0 = self._packets[0].ts if self._packets else 0.0
        span = (self._packets[-1].ts - self._t0) if len(self._packets) > 1 else 0.0
        self.speed = max(1.0, span / TARGET_REPLAY_SECONDS) if span > 0 else 1.0

        self._buffer: list = []
        self._idx = 0
        self._emit_times: deque = deque()      # wall-times of recent emits (for pps)
        self._alerts: list[dict] = []
        self._seen_alert_keys: set = set()

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.state = {
            "id": self.id, "scenario": scenario, "label": self.label,
            "status": "starting", "packets_total": len(self._packets),
            "packets": 0, "pps": 0, "flows": 0, "elapsed": 0.0,
            "progress": 0, "score": 0, "severity": "info",
            "distribution": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
            "alerts": [], "speed": round(self.speed, 1),
        }

    # ---- lifecycle ----
    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    # ---- replay loop ----
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
        # final tick + terminal status
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

        score, severity, dist = 0, "info", {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        if self._buffer:
            summary = preprocessor.preprocess(self._buffer, self.label)
            findings = _promote(summary.observations)
            score, severity, dist = score_findings(findings)
            for o in summary.observations:
                if o.severity_hint in _ALERT_LEVELS and o.id not in self._seen_alert_keys:
                    self._seen_alert_keys.add(o.id)
                    self._alerts.insert(0, {
                        "at": round(elapsed, 1), "type": o.type,
                        "severity": o.severity_hint, "description": o.description,
                        "mitre": list(getattr(o, "mitre_hints", []) or [])[:2],
                    })

        with self._lock:
            self.state.update({
                "status": self.state["status"], "packets": self._idx, "pps": pps,
                "flows": flows, "elapsed": round(elapsed, 1),
                "progress": int(100 * self._idx / max(1, len(self._packets))),
                "score": score, "severity": severity, "distribution": dist,
                "alerts": list(self._alerts[:30]),
            })

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self.state)


# ----------------------------- session manager -----------------------------
_SESSIONS: dict[str, LiveSession] = {}
_MGR_LOCK = threading.Lock()


def list_scenarios() -> list[dict]:
    return [{"id": k, "label": v["label"], "blurb": v["blurb"]} for k, v in SCENARIOS.items()]


def start_session(user_id: str, scenario: str) -> LiveSession:
    sess = LiveSession(user_id, scenario)
    with _MGR_LOCK:
        # one active session per user keeps the MVP simple
        for sid, s in list(_SESSIONS.items()):
            if s.user_id == user_id:
                s.stop()
                _SESSIONS.pop(sid, None)
        _SESSIONS[sess.id] = sess
    sess.start()
    return sess


def get_session(session_id: str) -> LiveSession | None:
    with _MGR_LOCK:
        return _SESSIONS.get(session_id)


def stop_session(session_id: str) -> bool:
    with _MGR_LOCK:
        s = _SESSIONS.get(session_id)
    if s:
        s.stop()
        return True
    return False
