import React, { useEffect, useRef, useState } from "react";
import { IconNetwork, IconPulse, IconShield, IconAlert, IconChip } from "../components/icons.jsx";
import KpiCard from "../components/KpiCard.jsx";
import ScoreGauge from "../components/ScoreGauge.jsx";
import { listScenarios, listInterfaces, startLive, stopLive, liveSocketUrl } from "../api/client.js";

const SEV_COLOR = { info: "#2dd4bf", low: "#facc15", medium: "#fb923c", high: "#ef5b15", critical: "#dc2626" };

export default function LiveCapturePage({ toast }) {
  const [source, setSource] = useState("replay");          // "replay" | "live"
  const [scenarios, setScenarios] = useState([]);
  const [scenario, setScenario] = useState("");
  const [interfaces, setInterfaces] = useState([]);
  const [iface, setIface] = useState("en0");
  const [running, setRunning] = useState(false);
  const [state, setState] = useState(null);
  const wsRef = useRef(null);
  const sessRef = useRef(null);

  useEffect(() => {
    listScenarios().then((s) => { setScenarios(s); if (s[0]) setScenario(s[0].id); }).catch(() => {});
    listInterfaces().then((ifs) => { setInterfaces(ifs); if (ifs[0]) setIface(ifs[0].name); }).catch(() => {});
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, []);

  const start = async () => {
    setState(null);
    try {
      const opts = source === "live" ? { source: "live", interface: iface, window: 30 }
                                     : { source: "replay", scenario };
      const snap = await startLive(opts);
      sessRef.current = snap.id;
      setState(snap);
      setRunning(true);
      const ws = new WebSocket(liveSocketUrl(snap.id));
      wsRef.current = ws;
      ws.onmessage = (e) => {
        try {
          const d = JSON.parse(e.data);
          if (d.error && !d.id) return;
          setState(d);
          if (d.status === "error") { toast?.(d.error || "Capture failed", "critical"); setRunning(false); ws.close(); }
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
  const isLive = (state ? state.source : source) === "live";
  const sev = s.severity || "info";
  const alerts = s.alerts || [];
  const windows = s.windows || [];

  return (
    <div className="view-enter">
      <div className="page-head">
        <h1>Live Capture <span className="live-on" style={{ opacity: running ? 1 : 0.3 }}>● LIVE</span></h1>
        <span className="sub">{isLive
          ? "Real-time monitoring of this device — captured in 30s windows, AI evaluates suspicious ones"
          : "Replayed capture streamed through the live detection engine"}</span>
      </div>

      <div className="card live-controls">
        <div className="live-source">
          <span className="muted" style={{ fontSize: 12 }}>Source</span>
          <select className="tb-select" value={source} disabled={running}
            onChange={(e) => setSource(e.target.value)}>
            <option value="replay">Replay demo</option>
            <option value="live">Live — this device</option>
          </select>

          {source === "replay" ? (
            <select className="tb-select" value={scenario} disabled={running}
              onChange={(e) => setScenario(e.target.value)} style={{ minWidth: 240 }}>
              {scenarios.map((sc) => <option key={sc.id} value={sc.id}>{sc.label}</option>)}
            </select>
          ) : (
            <>
              <select className="tb-select" value={iface} disabled={running}
                onChange={(e) => setIface(e.target.value)} style={{ minWidth: 160 }}>
                {interfaces.length
                  ? interfaces.map((i) => <option key={i.name} value={i.name}>{i.name}{i.desc ? ` — ${i.desc}` : ""}</option>)
                  : <option value="en0">en0</option>}
              </select>
              <span className="muted" style={{ fontSize: 11 }}>30s windows · AI on suspicious</span>
            </>
          )}
        </div>
        {!running
          ? <button className="btn primary" onClick={start} disabled={source === "replay" && !scenario}>▶ Start Monitoring</button>
          : <button className="btn" onClick={stop}>■ Stop</button>}
      </div>

      {isLive && state && (
        <div className="card" style={{ marginTop: 12, padding: "12px 16px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 13 }}>
            {s.status === "error" ? <span style={{ color: "var(--critical)" }}>⚠ {s.error}</span>
              : s.phase === "capturing" ? <><span className="live-on" style={{ marginLeft: 0 }}>●</span> Capturing window {s.window_index} on <code>{s.interface}</code>…</>
              : s.phase === "analyzing" ? <>Analyzing window {s.window_index}…</>
              : s.status === "stopped" ? "Monitoring stopped." : "Starting…"}
          </span>
          <span className="muted" style={{ fontSize: 12 }}>{s.ai_calls || 0} AI evaluations this session</span>
        </div>
      )}

      {!isLive && state && (
        <div className="card" style={{ padding: "12px 16px", marginTop: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "var(--muted)", marginBottom: 6 }}>
            <span>{s.label}</span>
            <span>{s.packets}/{s.packets_total} packets · {s.elapsed}s · {s.speed}× speed · {s.status}</span>
          </div>
          <div className="mini-progress"><div className="mini-bar" style={{ width: `${s.progress || 0}%` }} /></div>
        </div>
      )}

      <div className="kpi-grid" style={{ marginTop: 16 }}>
        <KpiCard index={0} label={isLive ? "Packets / window" : "Packets / sec"} value={s.packets || s.pps || 0}
          color="var(--accent)" Icon={IconNetwork} delta={running ? "streaming" : "idle"} deltaDir="flat" />
        <KpiCard index={1} label="Active flows" value={s.flows || 0} color="var(--brand)" Icon={IconPulse}
          delta="distinct" deltaDir="flat" />
        <KpiCard index={2} label={isLive ? "AI evaluations" : "Live alerts"} value={isLive ? (s.ai_calls || 0) : alerts.length}
          color={isLive ? "var(--brand)" : "var(--critical)"} Icon={isLive ? IconChip : IconAlert}
          delta={isLive ? "on suspicion" : (alerts.length ? "detections" : "none yet")} deltaDir={alerts.length ? "up" : "flat"} />
        <KpiCard index={3} label="Risk score" value={s.score || 0} color={SEV_COLOR[sev]} Icon={IconShield}
          delta={sev} deltaDir={(s.score || 0) > 50 ? "up" : "flat"} />
      </div>

      <div className="grid-2" style={{ marginTop: 20 }}>
        <div className="card">
          <div className="card-title">{isLive ? "Latest window risk" : "Live risk"}</div>
          {state ? <ScoreGauge score={s.score || 0} severity={sev} />
            : <div className="live-empty"><div className="live-radar"><span /><span /><span /></div>
                <p>Monitoring is not active.</p>
                <p className="muted" style={{ fontSize: 12 }}>
                  {isLive ? <>Pick an interface and press <b>Start Monitoring</b> to capture and evaluate this device's traffic. (Backend must run with <code>sudo</code>.)</>
                          : <>Pick a scenario and press <b>Start Monitoring</b> to watch the risk score climb in real time.</>}
                </p>
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
                  <span className="ct" style={{ minWidth: 56, textAlign: "right" }}>{isLive ? a.at : `${a.at}s`}</span>
                </div>
              ))}
            </div>
          ) : <div className="empty" style={{ fontSize: 13 }}>No alerts yet — they appear the moment a pattern emerges.</div>}
        </div>
      </div>

      {isLive && windows.length > 0 && (
        <div className="card" style={{ marginTop: 20 }}>
          <div className="card-title">Capture windows</div>
          <div className="rlist">
            {windows.map((w) => (
              <div key={w.index} className="rrow">
                <span className="dot" style={{ background: SEV_COLOR[w.severity] }} />
                <span className="chip">#{w.index}</span>
                <span className={`badge ${w.severity}`}>{w.severity}</span>
                {w.ai_used && <span className="mitre-tag">AI</span>}
                <span className="nm">{w.top && w.top.length ? w.top[0] : "No suspicious activity"}</span>
                <span className="muted" style={{ fontSize: 11 }}>{w.packets} pkts · {w.flows} flows</span>
                <span className="ct" style={{ color: SEV_COLOR[w.severity], minWidth: 40, textAlign: "right" }}>{w.score}</span>
                <span className="muted" style={{ fontSize: 11, minWidth: 64, textAlign: "right" }}>{w.at}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
