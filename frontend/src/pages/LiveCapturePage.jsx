import React, { useEffect, useRef, useState } from "react";
import { IconNetwork, IconPulse, IconShield, IconAlert } from "../components/icons.jsx";
import KpiCard from "../components/KpiCard.jsx";
import ScoreGauge from "../components/ScoreGauge.jsx";
import { listScenarios, startLive, stopLive, liveSocketUrl } from "../api/client.js";

const SEV_COLOR = { info: "#2dd4bf", low: "#facc15", medium: "#fb923c", high: "#ef5b15", critical: "#dc2626" };

export default function LiveCapturePage({ toast }) {
  const [scenarios, setScenarios] = useState([]);
  const [scenario, setScenario] = useState("");
  const [running, setRunning] = useState(false);
  const [state, setState] = useState(null);
  const wsRef = useRef(null);
  const sessRef = useRef(null);

  useEffect(() => {
    listScenarios().then((s) => { setScenarios(s); if (s[0]) setScenario(s[0].id); }).catch(() => {});
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, []);

  const start = async () => {
    try {
      const snap = await startLive(scenario);
      sessRef.current = snap.id;
      setState(snap);
      setRunning(true);
      const ws = new WebSocket(liveSocketUrl(snap.id));
      wsRef.current = ws;
      ws.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data);
          if (d.error) return;
          setState(d);
          if (d.status === "finished" || d.status === "stopped") { setRunning(false); ws.close(); }
        } catch { /* ignore */ }
      };
      ws.onclose = () => setRunning(false);
      ws.onerror = () => setRunning(false);
    } catch (err) {
      toast?.(err.message, "critical");
    }
  };

  const stop = async () => {
    try { if (sessRef.current) await stopLive(sessRef.current); } catch { /* ignore */ }
    if (wsRef.current) wsRef.current.close();
    setRunning(false);
  };

  const s = state || {};
  const sev = s.severity || "info";
  const alerts = s.alerts || [];

  return (
    <div className="view-enter">
      <div className="page-head">
        <h1>Live Capture <span className="live-on" style={{ opacity: running ? 1 : 0.3 }}>● LIVE</span></h1>
        <span className="sub">Real-time network monitoring — a replayed capture streamed through the live detection engine</span>
      </div>

      <div className="card live-controls">
        <div className="live-source">
          <span className="muted" style={{ fontSize: 12 }}>Scenario</span>
          <select className="tb-select" value={scenario} disabled={running}
            onChange={(e) => setScenario(e.target.value)} style={{ minWidth: 260 }}>
            {scenarios.map((sc) => <option key={sc.id} value={sc.id}>{sc.label}</option>)}
          </select>
        </div>
        {!running
          ? <button className="btn primary" onClick={start} disabled={!scenario}>▶ Start Monitoring</button>
          : <button className="btn" onClick={stop}>■ Stop</button>}
      </div>

      {state && (
        <div className="card" style={{ padding: "12px 16px", marginTop: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "var(--muted)", marginBottom: 6 }}>
            <span>{s.label}</span>
            <span>{s.packets}/{s.packets_total} packets · {s.elapsed}s · {s.speed}× speed · {s.status}</span>
          </div>
          <div className="mini-progress"><div className="mini-bar" style={{ width: `${s.progress || 0}%` }} /></div>
        </div>
      )}

      <div className="kpi-grid" style={{ marginTop: 16 }}>
        <KpiCard index={0} label="Packets / sec" value={s.pps || 0} color="var(--accent)" Icon={IconNetwork}
          delta={running ? "streaming" : "idle"} deltaDir="flat" />
        <KpiCard index={1} label="Active flows" value={s.flows || 0} color="var(--brand)" Icon={IconPulse}
          delta="distinct" deltaDir="flat" />
        <KpiCard index={2} label="Live alerts" value={alerts.length} color="var(--critical)" Icon={IconAlert}
          delta={alerts.length ? "detections" : "none yet"} deltaDir={alerts.length ? "up" : "flat"} />
        <KpiCard index={3} label="Risk score" value={s.score || 0} color={SEV_COLOR[sev]} Icon={IconShield}
          delta={sev} deltaDir={(s.score || 0) > 50 ? "up" : "flat"} />
      </div>

      <div className="grid-2" style={{ marginTop: 20 }}>
        <div className="card">
          <div className="card-title">Live risk</div>
          {state ? <ScoreGauge score={s.score || 0} severity={sev} />
            : <div className="live-empty"><div className="live-radar"><span /><span /><span /></div>
                <p>Monitoring is not active.</p>
                <p className="muted" style={{ fontSize: 12 }}>Pick a scenario and press <b>Start Monitoring</b> to watch the risk score climb in real time.</p>
              </div>}
        </div>

        <div className="card live-stage">
          <div className="card-title">Live alert feed {alerts.length > 0 && <span className="badge critical">{alerts.length}</span>}</div>
          {alerts.length ? (
            <div className="rlist live-feed">
              {alerts.map((a, i) => (
                <div key={i} className="rrow live-alert">
                  <span className="dot" style={{ background: SEV_COLOR[a.severity] }} />
                  <span className={`badge ${a.severity}`}>{a.severity}</span>
                  <span className="nm">{a.description}</span>
                  {(a.mitre || []).map((m) => <span key={m} className="mitre-tag">{m}</span>)}
                  <span className="ct" style={{ minWidth: 48, textAlign: "right" }}>{a.at}s</span>
                </div>
              ))}
            </div>
          ) : <div className="empty" style={{ fontSize: 13 }}>No alerts yet — they appear the moment a pattern emerges.</div>}
        </div>
      </div>
    </div>
  );
}
