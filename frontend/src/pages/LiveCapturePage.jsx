import React from "react";
import { IconNetwork, IconPulse, IconShield, IconAlert } from "../components/icons.jsx";

// Placeholder preview of the planned live-capture mode. No backend yet — the
// controls are intentionally disabled and the panels show what the live view
// will look like once real-time monitoring is wired up.
const PLANNED = [
  ["Real-time ingest", "Stream packets from a replayed capture (or, later, a live interface) through the same pipeline, at true timing."],
  ["Incremental analysis", "A rolling window re-runs detection every few seconds while traffic flows — the risk score updates continuously."],
  ["Throttled AI", "The deterministic engine runs constantly; the AI is only called on meaningful change, so it stays fast and cheap."],
  ["Live alerts", "Findings appear the moment a pattern emerges (e.g. beaconing after ~30s), pushed over the existing WebSocket."],
  ["Snapshot to report", "Freeze any moment of a live session into a full TLP:AMBER incident report."],
];

export default function LiveCapturePage() {
  return (
    <div className="view-enter">
      <div className="page-head">
        <h1>Live Capture <span className="preview-badge">PREVIEW</span></h1>
        <span className="sub">Real-time network monitoring — coming soon</span>
      </div>

      {/* Control bar (disabled preview) */}
      <div className="card live-controls">
        <div className="live-source">
          <span className="muted" style={{ fontSize: 12 }}>Capture source</span>
          <select className="tb-select" disabled>
            <option>Bundled scenario — njRAT beaconing</option>
          </select>
          <select className="tb-select" disabled>
            <option>Window: 5s</option>
          </select>
        </div>
        <button className="btn primary" disabled>▶ Start Monitoring</button>
      </div>

      {/* Live stat tiles (placeholder values) */}
      <div className="kpi-grid live-dim">
        <Stat icon={<IconNetwork size={20} />} label="Packets / sec" />
        <Stat icon={<IconPulse size={20} />} label="Active flows" />
        <Stat icon={<IconAlert size={20} />} label="Live alerts" />
        <Stat icon={<IconShield size={20} />} label="Risk score" />
      </div>

      <div className="grid-2" style={{ marginTop: 20 }}>
        <div className="card">
          <div className="card-title">What live capture will do</div>
          <div className="rlist">
            {PLANNED.map(([title, desc]) => (
              <div key={title} className="plan-row">
                <span className="plan-dot" />
                <div>
                  <div className="plan-title">{title}</div>
                  <div className="plan-desc">{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="card live-stage">
          <div className="card-title">Live stream</div>
          <div className="live-empty">
            <div className="live-radar"><span /><span /><span /></div>
            <p>Monitoring is not active.</p>
            <p className="muted" style={{ fontSize: 12 }}>
              This panel will show a live packet stream, a scrolling timeline, and the
              risk gauge climbing in real time as an attack unfolds. Switch to
              <b> File Analysis</b> to analyze a capture now.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function Stat({ icon, label }) {
  return (
    <div className="kpi">
      <div className="kpi-top">
        <span className="kpi-label">{label}</span>
        <span className="kpi-icon" style={{ background: "color-mix(in srgb, var(--brand) 12%, transparent)", color: "var(--brand)" }}>{icon}</span>
      </div>
      <div className="kpi-val" style={{ opacity: 0.35 }}>—</div>
      <div className="kpi-delta flat">awaiting capture</div>
    </div>
  );
}
