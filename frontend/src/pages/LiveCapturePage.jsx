import React, { useEffect, useRef, useState } from "react";
import { LineChart, Line, ResponsiveContainer, YAxis, Tooltip } from "recharts";
import { IconNetwork, IconPulse, IconShield, IconAlert, IconChip, IconReport } from "../components/icons.jsx";
import KpiCard from "../components/KpiCard.jsx";
import ScoreGauge from "../components/ScoreGauge.jsx";
import GeoMap from "../components/GeoMap.jsx";
import { listScenarios, listInterfaces, startLive, stopLive, snapshotLive, liveSocketUrl } from "../api/client.js";

const SEV_COLOR = { info: "#2dd4bf", low: "#facc15", medium: "#fb923c", high: "#ef5b15", critical: "#dc2626" };

export default function LiveCapturePage({ toast }) {
  const [source, setSource] = useState("replay");
  const [scenarios, setScenarios] = useState([]);
  const [scenario, setScenario] = useState("");
  const [interfaces, setInterfaces] = useState([]);
  const [iface, setIface] = useState("en0");
  const [showAll, setShowAll] = useState(false);
  const [windowSec, setWindowSec] = useState(30);
  const [sensitivity, setSensitivity] = useState("medium");
  const [running, setRunning] = useState(false);
  const [saving, setSaving] = useState(false);
  const [state, setState] = useState(null);
  const wsRef = useRef(null);
  const sessRef = useRef(null);

  useEffect(() => {
    listScenarios().then((s) => { setScenarios(s); if (s[0]) setScenario(s[0].id); }).catch(() => {});
    listInterfaces().then((d) => {
      setInterfaces(d.interfaces || []);
      setIface(d.default || (d.interfaces && d.interfaces[0] && d.interfaces[0].name) || "en0");
    }).catch(() => {});
    return () => { if (wsRef.current) wsRef.current.close(); };
  }, []);

  const start = async () => {
    setState(null);
    try {
      const opts = source === "live"
        ? { source: "live", interface: iface, window: windowSec, sensitivity }
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
    } catch (err) { toast?.(err.message, "critical"); }
  };

  const stop = async () => {
    try { if (sessRef.current) await stopLive(sessRef.current); } catch { /* ignore */ }
    if (wsRef.current) wsRef.current.close();
    setRunning(false);
  };

  const save = async () => {
    if (!sessRef.current) return;
    setSaving(true);
    try {
      const r = await snapshotLive(sessRef.current);
      toast?.(`Saved as case ${r.case_number} — ${r.severity} (${r.score})`, "info");
    } catch (err) { toast?.(err.message, "critical"); }
    finally { setSaving(false); }
  };

  const s = state || {};
  const isLive = (state ? state.source : source) === "live";
  const sev = s.severity || "info";
  const alerts = s.alerts || [];
  const windows = s.windows || [];
  const hist = (s.score_history || []).map(([x, score]) => ({ x, score }));
  const usage = s.usage || {};
  const tokens = (usage.prompt_tokens || 0) + (usage.completion_tokens || 0);
  const hasData = !!(s.score || s.packets || windows.length || (s.packets_total && s.packets));

  return (
    <div className="view-enter">
      <div className="page-head">
        <h1>Live Capture <span className="live-on" style={{ opacity: running ? 1 : 0.3 }}>● LIVE</span></h1>
        <span className="sub">{isLive
          ? "Real-time monitoring of this device — 30s windows, AI evaluates suspicious ones"
          : "Replayed capture streamed through the live detection engine"}</span>
      </div>

      <div className="card live-controls">
        <div className="live-source">
          <span className="muted" style={{ fontSize: 12 }}>Source</span>
          <select className="tb-select" value={source} disabled={running} onChange={(e) => setSource(e.target.value)}>
            <option value="replay">Replay demo</option>
            <option value="live">Live — this device</option>
          </select>

          {source === "replay" ? (
            <select className="tb-select" value={scenario} disabled={running}
              onChange={(e) => setScenario(e.target.value)} style={{ minWidth: 230 }}>
              {scenarios.map((sc) => <option key={sc.id} value={sc.id}>{sc.label}</option>)}
            </select>
          ) : (
            <>
              {showAll ? (
                <select className="tb-select" value={iface} disabled={running}
                  onChange={(e) => setIface(e.target.value)} style={{ minWidth: 200 }}>
                  {interfaces.map((i) => <option key={i.name} value={i.name}>{i.name}{i.desc ? ` — ${i.desc}` : ""}</option>)}
                </select>
              ) : (
                <span style={{ fontSize: 13 }}>Auto · <code style={{ color: "var(--brand)" }}>{iface}</code>
                  {!running && <button onClick={() => setShowAll(true)} style={{ marginLeft: 8, background: "none", border: "none", color: "var(--muted)", fontSize: 12, cursor: "pointer", textDecoration: "underline" }}>change</button>}
                </span>
              )}
              <select className="tb-select" value={windowSec} disabled={running} onChange={(e) => setWindowSec(+e.target.value)} title="Window length">
                <option value={15}>15s windows</option>
                <option value={30}>30s windows</option>
                <option value={60}>60s windows</option>
              </select>
              <select className="tb-select" value={sensitivity} disabled={running} onChange={(e) => setSensitivity(e.target.value)} title="AI trigger sensitivity">
                <option value="low">AI: low (any signal)</option>
                <option value="medium">AI: medium</option>
                <option value="high">AI: high (only serious)</option>
              </select>
            </>
          )}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {hasData && <button className="btn" onClick={save} disabled={saving}>{saving ? "Saving…" : "💾 Save as case"}</button>}
          {!running
            ? <button className="btn primary" onClick={start} disabled={source === "replay" && !scenario}>▶ Start Monitoring</button>
            : <button className="btn" onClick={stop}>■ Stop</button>}
        </div>
      </div>

      {isLive && state && (
        <div className="card" style={{ marginTop: 12, padding: "12px 16px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
          <span style={{ fontSize: 13 }}>
            {s.status === "error" ? <span style={{ color: "var(--critical)" }}>⚠ {s.error}</span>
              : s.learning ? <><span className="live-on" style={{ marginLeft: 0 }}>●</span> Learning your normal traffic… (window {s.window_index})</>
              : s.phase === "capturing" ? <><span className="live-on" style={{ marginLeft: 0 }}>●</span> Capturing window {s.window_index} on <code>{s.interface}</code>…</>
              : s.phase === "analyzing" ? <>Analyzing window {s.window_index}…</>
              : s.status === "stopped" ? "Monitoring stopped." : "Starting…"}
          </span>
          <span className="muted" style={{ fontSize: 12 }}>
            {s.baseline_size || 0} known endpoints · {s.ai_calls || 0} AI evals · {tokens.toLocaleString()} tokens
            {usage.cost_usd ? ` · $${usage.cost_usd.toFixed(4)}` : ""}
          </span>
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
        <KpiCard index={1} label="Active flows" value={s.flows || 0} color="var(--brand)" Icon={IconPulse} delta="distinct" deltaDir="flat" />
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
                  {isLive ? <>Pick an interface and press <b>Start Monitoring</b> to capture this device's traffic. (Backend must run with <code>sudo</code>.)</>
                          : <>Pick a scenario and press <b>Start Monitoring</b> to watch the risk climb in real time.</>}
                </p>
              </div>}
        </div>

        <div className="card">
          <div className="card-title">Risk trend</div>
          {hist.length > 1 ? (
            <ResponsiveContainer width="100%" height={230}>
              <LineChart data={hist} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <YAxis domain={[0, 100]} tick={{ fill: "#9DB0B6", fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "#171A2A", border: "1px solid #2D3250", borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: "#9DB0B6" }} formatter={(v) => [v, "score"]} labelFormatter={(l) => isLive ? `window ${l}` : `${l}s`} />
                <Line type="monotone" dataKey="score" stroke={SEV_COLOR[sev]} strokeWidth={2.5} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          ) : <div className="empty" style={{ fontSize: 13 }}>Trend appears as data comes in.</div>}
        </div>
      </div>

      <div className="grid-2" style={{ marginTop: 20 }}>
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

        <div className="card">
          <div className="card-title">Connection map</div>
          <GeoMap geo={s.geo} reputation={s.reputation} />
        </div>
      </div>

      {isLive && windows.length > 0 && (
        <div className="card" style={{ marginTop: 20 }}>
          <div className="card-title">Capture windows</div>
          <div className="rlist">
            {windows.map((w) => (
              <div key={w.index} className="rrow" style={{ alignItems: "flex-start" }}>
                <span className="dot" style={{ background: SEV_COLOR[w.severity], marginTop: 6 }} />
                <span className="chip">#{w.index}</span>
                <span className={`badge ${w.severity}`}>{w.severity}</span>
                {w.learning && <span className="mitre-tag">baseline</span>}
                {w.ai_used && <span className="mitre-tag">AI</span>}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="nm">{w.top && w.top.length ? w.top[0] : "No suspicious activity"}</div>
                  {w.note && <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>{w.note}</div>}
                </div>
                <span className="muted" style={{ fontSize: 11 }}>{w.packets} pkts · {w.flows} flows{w.new_endpoints ? ` · ${w.new_endpoints} new` : ""}</span>
                <span className="ct" style={{ color: SEV_COLOR[w.severity], minWidth: 36, textAlign: "right" }}>{w.score}</span>
                <span className="muted" style={{ fontSize: 11, minWidth: 64, textAlign: "right" }}>{w.at}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
