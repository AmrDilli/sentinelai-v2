import React from "react";
import KpiCard from "../components/KpiCard.jsx";
import CoverageRadar from "../components/CoverageRadar.jsx";
import SeverityChart from "../components/SeverityChart.jsx";
import ActivityHeatmap from "../components/ActivityHeatmap.jsx";
import { IconAlert, IconPulse, IconBell, IconSearch, IconNetwork, IconChip, IconCloud } from "../components/icons.jsx";

const SEV_COLOR = { info: "#2dd4bf", low: "#facc15", medium: "#fb923c", high: "#ef5b15", critical: "#dc2626" };
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const MOD_ICON = { network: IconNetwork, forensics: IconCloud, malware: IconChip };

export default function DashboardPage({ analyses, onOpen, onNavigate }) {
  const done = analyses.filter((a) => a.status === "completed");
  const reports = done.map((a) => a.report).filter(Boolean);
  const running = analyses.filter((a) => a.status === "running").length;

  // aggregate severity distribution across all completed cases
  const dist = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const r of reports) {
    for (const [k, v] of Object.entries(r.severity_distribution || {})) dist[k] += v;
  }
  const activeAlerts = dist.low + dist.medium + dist.high + dist.critical;

  // Priority queue: the high/critical findings that actually need attention now
  const priority = [];
  for (const a of done) {
    for (const f of a.report?.findings || []) {
      if (f.severity === "high" || f.severity === "critical") {
        priority.push({
          caseId: a.id, file: a.filename, module: a.module,
          title: f.title, severity: f.severity, conf: f.confidence || 0,
          mitre: f.mitre_techniques || [],
        });
      }
    }
  }
  priority.sort((x, y) => RANK[y.severity] - RANK[x.severity] || y.conf - x.conf);

  if (!done.length && !running) {
    return (
      <div className="view-enter">
        <div className="page-head"><h1>Security Overview</h1>
          <span className="sub">Live SOC console</span></div>
        <div className="card empty">
          <span className="big">⌖</span>
          No analyses yet. Ingest an artifact from the Investigations tab to begin monitoring.
        </div>
      </div>
    );
  }

  return (
    <div className="view-enter">
      <div className="page-head">
        <h1>Security Overview</h1>
        <span className="sub">Live SOC console — {done.length} case{done.length === 1 ? "" : "s"} analyzed{running ? `, ${running} analyzing` : ""}</span>
      </div>

      {/* The numbers that drive action — each opens the relevant section */}
      <div className="kpi-grid">
        <KpiCard index={0} label="Critical Alerts" value={dist.critical} color="var(--critical)" Icon={IconAlert}
          delta={dist.critical > 0 ? "Immediate action" : "None active"} deltaDir={dist.critical > 0 ? "up" : "down"}
          onClick={() => onNavigate("alerts")} />
        <KpiCard index={1} label="High Alerts" value={dist.high} color="var(--high)" Icon={IconPulse}
          delta={dist.high > 0 ? "Investigate soon" : "None active"} deltaDir={dist.high > 0 ? "up" : "down"}
          onClick={() => onNavigate("alerts")} />
        <KpiCard index={2} label="Active Alerts" value={activeAlerts} color="var(--brand)" Icon={IconBell}
          delta="across all cases" deltaDir="flat"
          onClick={() => onNavigate("alerts")} />
        <KpiCard index={3} label="Open Cases" value={done.length} color="var(--accent)" Icon={IconSearch}
          delta={running ? `${running} analyzing now` : "all complete"} deltaDir="flat"
          onClick={() => onNavigate("investigations")} />
      </div>

      {/* Priority queue + severity mix */}
      <div className="grid-2">
        <div className="card">
          <div className="card-title">Priority Queue — needs attention
            <span className="card-link" onClick={() => onNavigate("alerts")}>All alerts ›</span>
          </div>
          {priority.length ? (
            <div className="rlist">
              {priority.slice(0, 7).map((p, i) => {
                const Mod = MOD_ICON[p.module] || IconChip;
                return (
                  <div key={i} className="rrow" onClick={() => onOpen(p.caseId)}>
                    <span className="dot" style={{ background: SEV_COLOR[p.severity] }} />
                    <span className={`badge ${p.severity}`}>{p.severity}</span>
                    <span className="nm">{p.title}</span>
                    {p.mitre.slice(0, 2).map((m) => <span key={m} className="mitre-tag">{m}</span>)}
                    <span className="chip"><Mod size={12} /> {p.file}</span>
                  </div>
                );
              })}
            </div>
          ) : <div className="empty"><span className="big">✓</span>No high or critical alerts. You're clear.</div>}
        </div>

        <div className="card clickable" onClick={() => onNavigate("alerts")}>
          <div className="card-title">Severity Mix <span className="card-link">Alerts ›</span></div>
          {reports.length ? <SeverityChart distribution={dist} height={250} />
            : <div className="empty">No findings yet</div>}
        </div>
      </div>

      {/* Situational awareness: what attack stages, and when */}
      <div className="grid-2e" style={{ marginBottom: 20 }}>
        <div className="card clickable" onClick={() => onNavigate("investigations")}>
          <div className="card-title">ATT&amp;CK Coverage <span className="card-link">Investigate ›</span></div>
          {reports.length ? <CoverageRadar analyses={done} />
            : <div className="empty">No data yet</div>}
        </div>
        <div className="card clickable" onClick={() => onNavigate("trends")}>
          <div className="card-title">Threat Activity <span className="card-link">Trends ›</span></div>
          <ActivityHeatmap analyses={done} />
        </div>
      </div>

      {/* Latest detections */}
      <div className="card">
        <div className="card-title">Recent Detections
          <span className="card-link" onClick={() => onNavigate("investigations")}>All cases ›</span>
        </div>
        {done.length ? (
          <div className="rlist">
            {done.slice(0, 8).map((a) => (
              <div key={a.id} className="rrow" onClick={() => onOpen(a.id)}>
                <span className="dot" style={{ background: SEV_COLOR[a.severity] || "#64748b" }} />
                <span className="nm">{a.filename}</span>
                <span className={`badge ${a.severity}`}>{a.severity}</span>
                <span className="ct" style={{ color: SEV_COLOR[a.severity], minWidth: 44, textAlign: "right" }}>{a.score}</span>
                <span className="chip">{a.module}</span>
              </div>
            ))}
          </div>
        ) : <div className="empty">No completed cases yet.</div>}
      </div>
    </div>
  );
}
