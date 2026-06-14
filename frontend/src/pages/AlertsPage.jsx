import React, { useState } from "react";
import { IconNetwork, IconChip, IconCloud, IconDots } from "../components/icons.jsx";

const MODULE_ICON = { network: IconNetwork, forensics: IconCloud, malware: IconChip };
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SEV_ORDER = ["critical", "high", "medium", "low"];

// Flatten every finding across completed cases into a single alert feed.
function buildAlerts(analyses) {
  const alerts = [];
  for (const a of analyses) {
    if (a.status !== "completed" || !a.report) continue;
    for (const f of a.report.findings || []) {
      if (f.severity === "info") continue;
      alerts.push({
        caseId: a.id, file: a.filename, module: a.module,
        title: f.title, description: f.description, severity: f.severity,
        mitre: f.mitre_techniques || [], score: a.report.score,
      });
    }
  }
  return alerts.sort((x, y) => RANK[y.severity] - RANK[x.severity]);
}

export default function AlertsPage({ analyses, onOpen, onGoToInvestigations }) {
  const [focus, setFocus] = useState(false);
  const [sev, setSev] = useState("all");
  const [mod, setMod] = useState("all");
  const [menu, setMenu] = useState(null);

  const allAlerts = buildAlerts(analyses);
  let alerts = allAlerts;
  if (focus) alerts = alerts.filter((a) => ["critical", "high"].includes(a.severity));
  if (sev !== "all") alerts = alerts.filter((a) => a.severity === sev);
  if (mod !== "all") alerts = alerts.filter((a) => a.module === mod);

  const counts = Object.fromEntries(
    SEV_ORDER.map((s) => [s, allAlerts.filter((a) => a.severity === s).length]));
  const running = analyses.filter((a) => a.status === "running");
  const completed = analyses.filter((a) => a.status === "completed").length;

  return (
    <div className="view-enter">
      <div className="page-head">
        <h1>Alert Queue</h1>
        <span className="sub">Live triage feed — every finding across {completed} analyzed case{completed === 1 ? "" : "s"}</span>
      </div>

      {/* Severity summary — click a tile to filter the queue */}
      <div className="queue-stats">
        {SEV_ORDER.map((s) => (
          <button key={s} className={`qstat ${s} ${sev === s ? "active" : ""}`}
            onClick={() => setSev(sev === s ? "all" : s)}>
            <span className="qstat-num">{counts[s]}</span>
            <span className="qstat-lbl">{s}</span>
          </button>
        ))}
      </div>

      {running.length > 0 && (
        <div className="card" style={{ marginBottom: 18 }}>
          <div className="card-title">Analyzing</div>
          {running.map((a) => (
            <div key={a.id} style={{ marginBottom: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13 }}>
                <span>{a.filename}</span><span className="muted">{a.stage || "queued"} · {a.progress || 0}%</span>
              </div>
              <div className="mini-progress"><div className="mini-bar" style={{ width: `${a.progress || 0}%` }} /></div>
            </div>
          ))}
        </div>
      )}

      <div className="focus-bar">
        <div className={`switch ${focus ? "on" : ""}`} onClick={() => setFocus(!focus)} />
        <div>
          <div style={{ fontWeight: 600, fontSize: 14 }}>Focus Mode</div>
          <div className="muted" style={{ fontSize: 12 }}>Show only critical &amp; high severity</div>
        </div>
        <div className="filters">
          <select className="tb-select" value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="all">All Severities</option>
            <option value="critical">Critical</option><option value="high">High</option>
            <option value="medium">Medium</option><option value="low">Low</option>
          </select>
          <select className="tb-select" value={mod} onChange={(e) => setMod(e.target.value)}>
            <option value="all">All Sources</option>
            <option value="network">Network</option><option value="forensics">Forensics</option><option value="malware">Malware</option>
          </select>
        </div>
      </div>

      {alerts.length === 0 ? (
        <div className="card empty">
          <span className="big">✓</span>
          {allAlerts.length === 0 ? (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10 }}>
              <span>No active alerts. Ingest an artifact to generate findings.</span>
              <button className="btn primary" onClick={onGoToInvestigations}>Go to Investigations to upload</button>
            </div>
          ) : "No alerts match the current filters."}
        </div>
      ) : (
        <div className="alert-grid stagger">
          {alerts.map((a, i) => {
            const Mod = MODULE_ICON[a.module] || IconChip;
            return (
              <div key={i} className={`alert ${a.severity}`} onClick={() => onOpen(a.caseId)}>
                <div className="alert-head">
                  <span className={`badge ${a.severity}`}>{a.severity}</span>
                  <span className="alert-meta"><Mod size={14} /> {a.module}</span>
                  <div className="tb-icon" style={{ width: 28, height: 28 }}
                    onClick={(e) => { e.stopPropagation(); setMenu(menu === i ? null : i); }}>
                    <IconDots size={15} />
                  </div>
                </div>
                <h3>{a.title}</h3>
                <p>{a.description}</p>
                <div className="alert-foot">
                  <span className="chip">{a.file}</span>
                  {a.mitre.slice(0, 3).map((m) => <span key={m} className="mitre-tag">{m}</span>)}
                  {menu === i && (
                    <div style={{ marginLeft: "auto", display: "flex", gap: 6 }} onClick={(e) => e.stopPropagation()}>
                      <button className="btn sm primary" onClick={() => onOpen(a.caseId)}>Investigate</button>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
