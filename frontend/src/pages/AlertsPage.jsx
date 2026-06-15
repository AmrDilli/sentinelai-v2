import React, { useState, useEffect } from "react";
import { IconNetwork, IconChip, IconCloud, IconCheck, IconAlert } from "../components/icons.jsx";
import { setTriage } from "../api/client.js";

const MODULE_ICON = { network: IconNetwork, forensics: IconCloud, malware: IconChip };
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const SEV_ORDER = ["critical", "high", "medium", "low"];

// Flatten every finding across completed cases into a single alert feed,
// carrying its finding index + triage state.
function buildAlerts(analyses, overrides) {
  const alerts = [];
  for (const a of analyses) {
    if (a.status !== "completed" || !a.report) continue;
    const tri = a.triage || {};
    (a.report.findings || []).forEach((f, idx) => {
      if (f.severity === "info") return;
      const key = `${a.id}:${idx}`;
      const status = overrides[key] ?? tri[idx] ?? "new";
      alerts.push({
        caseId: a.id, findingIndex: idx, key, file: a.filename, module: a.module,
        title: f.title, description: f.description, severity: f.severity,
        mitre: f.mitre_techniques || [], status,
      });
    });
  }
  return alerts.sort((x, y) =>
    (y.status === "escalated") - (x.status === "escalated")
    || (x.status === "dismissed") - (y.status === "dismissed")
    || RANK[y.severity] - RANK[x.severity]);
}

export default function AlertsPage({ analyses, onOpen, onGoToInvestigations, focus: arriveFocus }) {
  const [focus, setFocus] = useState(false);
  const [sev, setSev] = useState("all");
  const [mod, setMod] = useState("all");
  const [showDismissed, setShowDismissed] = useState(false);
  const [overrides, setOverrides] = useState({});
  const [flash, setFlash] = useState(null);

  // Arriving from a dashboard KPI: filter to that severity and glow its tile briefly.
  useEffect(() => {
    if (!arriveFocus?.sev) return;
    setSev(arriveFocus.sev);
    setFlash(arriveFocus.sev);
    const t = setTimeout(() => setFlash(null), 2800);
    return () => clearTimeout(t);
  }, [arriveFocus?.ts]);

  const triage = (e, alert, status) => {
    e.stopPropagation();
    const next = alert.status === status ? "new" : status; // click active state to clear
    setOverrides((o) => ({ ...o, [alert.key]: next }));
    setTriage(alert.caseId, alert.findingIndex, next).catch(() => {});
  };

  const allAlerts = buildAlerts(analyses, overrides);
  let alerts = allAlerts;
  if (!showDismissed) alerts = alerts.filter((a) => a.status !== "dismissed");
  if (focus) alerts = alerts.filter((a) => ["critical", "high"].includes(a.severity));
  if (sev !== "all") alerts = alerts.filter((a) => a.severity === sev);
  if (mod !== "all") alerts = alerts.filter((a) => a.module === mod);

  // severity tiles count only outstanding (non-dismissed) alerts
  const active = allAlerts.filter((a) => a.status !== "dismissed");
  const counts = Object.fromEntries(SEV_ORDER.map((s) => [s, active.filter((a) => a.severity === s).length]));
  const dismissedCount = allAlerts.length - active.length;
  const running = analyses.filter((a) => a.status === "running");
  const completed = analyses.filter((a) => a.status === "completed").length;

  return (
    <div className="view-enter">
      <div className="page-head">
        <h1>Alert Queue</h1>
        <span className="sub">Live triage feed — {active.length} outstanding across {completed} analyzed case{completed === 1 ? "" : "s"}</span>
      </div>

      <div className="queue-stats">
        {SEV_ORDER.map((s) => (
          <button key={s} className={`qstat ${s} ${sev === s ? "active" : ""} ${flash === s ? "flash" : ""}`}
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
          {dismissedCount > 0 && (
            <button className="btn sm" onClick={() => setShowDismissed((v) => !v)}>
              {showDismissed ? "Hide" : "Show"} dismissed ({dismissedCount})
            </button>
          )}
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
          ) : "No alerts match the current filters — queue clear."}
        </div>
      ) : (
        <div className="alert-grid stagger">
          {alerts.map((a) => {
            const Mod = MODULE_ICON[a.module] || IconChip;
            return (
              <div key={a.key} className={`alert ${a.severity} ${a.status === "dismissed" ? "dismissed" : ""}`}
                onClick={() => onOpen(a.caseId)}>
                <div className="alert-head">
                  <span className={`badge ${a.severity}`}>{a.severity}</span>
                  {a.status !== "new" && <span className={`status-tag ${a.status}`}>{a.status}</span>}
                  <span className="alert-meta"><Mod size={14} /> {a.module}</span>
                </div>
                <h3>{a.title}</h3>
                <p>{a.description}</p>
                <div className="alert-foot">
                  <span className="chip">{a.file}</span>
                  {a.mitre.slice(0, 2).map((m) => <span key={m} className="mitre-tag">{m}</span>)}
                  <div className="triage" onClick={(e) => e.stopPropagation()}>
                    <button className={`ack ${a.status === "acknowledged" ? "on" : ""}`}
                      title="Acknowledge" onClick={(e) => triage(e, a, "acknowledged")}>
                      <IconCheck size={12} /> Ack
                    </button>
                    <button className={`esc ${a.status === "escalated" ? "on" : ""}`}
                      title="Escalate" onClick={(e) => triage(e, a, "escalated")}>
                      <IconAlert size={12} /> Escalate
                    </button>
                    <button className="dis" title="Dismiss" onClick={(e) => triage(e, a, "dismissed")}>✕</button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
