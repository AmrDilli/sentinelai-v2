import React from "react";
import KpiCard from "../components/KpiCard.jsx";
import CoverageRadar from "../components/CoverageRadar.jsx";
import SeverityChart from "../components/SeverityChart.jsx";
import ActivityHeatmap from "../components/ActivityHeatmap.jsx";
import { IconAlert, IconShield, IconClock, IconTrend } from "../components/icons.jsx";

const SEV_COLOR = { info: "#64748b", low: "#38bdf8", medium: "#f59e0b", high: "#f97316", critical: "#ef4444" };

export default function DashboardPage({ analyses, onOpen }) {
  const done = analyses.filter((a) => a.status === "completed");
  const reports = done.map((a) => a.report).filter(Boolean);

  // aggregate severity distribution + finding counts
  const dist = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  let totalFindings = 0, critical = 0, scoreSum = 0;
  const threatTypes = {};
  for (const r of reports) {
    for (const [k, v] of Object.entries(r.severity_distribution || {})) dist[k] += v;
    totalFindings += (r.findings || []).length;
    critical += (r.severity === "critical" ? 1 : 0);
    scoreSum += r.score || 0;
    for (const f of r.findings || []) {
      const t = f.title || "Other";
      threatTypes[t] = (threatTypes[t] || 0) + 1;
    }
  }
  const avgScore = reports.length ? Math.round(scoreSum / reports.length) : 0;
  const topThreats = Object.entries(threatTypes).sort((a, b) => b[1] - a[1]).slice(0, 6);

  return (
    <div className="view-enter">
      <div className="page-head">
        <h1>Security Dashboard</h1>
        <span className="sub">Aggregate view across {done.length} analyzed case{done.length === 1 ? "" : "s"}</span>
      </div>

      <div className="kpi-grid">
        <KpiCard index={0} label="Cases Analyzed" value={done.length} color="var(--brand)" Icon={IconShield}
          delta={`${analyses.filter((a) => a.status === "running").length} in progress`} deltaDir="flat" />
        <KpiCard index={1} label="Critical Cases" value={critical} color="var(--critical)" Icon={IconAlert}
          delta={critical > 0 ? "Immediate attention" : "None active"} deltaDir={critical > 0 ? "up" : "down"} />
        <KpiCard index={2} label="Total Findings" value={totalFindings} color="var(--high)" Icon={IconTrend}
          delta={`across ${reports.length} report${reports.length === 1 ? "" : "s"}`} deltaDir="flat" />
        <KpiCard index={3} label="Avg Risk Score" value={avgScore} suffix="/100" color="var(--medium)" Icon={IconClock}
          delta={avgScore >= 65 ? "Elevated" : "Nominal"} deltaDir={avgScore >= 65 ? "up" : "down"} />
      </div>

      <div className="grid-3">
        <div className="card">
          <div className="card-title">Severity Distribution</div>
          {reports.length ? <SeverityChart distribution={dist} height={250} />
            : <div className="empty"><span className="big">◔</span>No data yet</div>}
        </div>
        <div className="card">
          <div className="card-title">ATT&amp;CK Coverage</div>
          {reports.length ? <CoverageRadar analyses={done} />
            : <div className="empty">No data yet</div>}
        </div>
        <div className="card">
          <div className="card-title">Top Threat Types</div>
          {topThreats.length ? (
            <div className="rlist">
              {topThreats.map(([name, count], i) => (
                <div key={name} className="rrow">
                  <span className="dot" style={{ background: Object.values(SEV_COLOR)[i % 5] }} />
                  <span className="nm">{name}</span>
                  <span className="ct">{count}</span>
                </div>
              ))}
            </div>
          ) : <div className="empty">No findings yet</div>}
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: 20 }}>
        <div className="card">
          <div className="card-title">Weekly Threat Activity</div>
          <ActivityHeatmap analyses={done} />
        </div>
        <div className="card">
          <div className="card-title">Quick Stats</div>
          <div className="rlist">
            <div className="rrow"><span className="nm">High / Critical findings</span><span className="ct" style={{ color: "var(--critical)" }}>{dist.high + dist.critical}</span></div>
            <div className="rrow"><span className="nm">Medium findings</span><span className="ct" style={{ color: "var(--medium)" }}>{dist.medium}</span></div>
            <div className="rrow"><span className="nm">Low / Info</span><span className="ct" style={{ color: "var(--low)" }}>{dist.low + dist.info}</span></div>
            <div className="rrow"><span className="nm">Modules used</span><span className="ct">{new Set(done.map(a => a.module)).size}</span></div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-title">Recent Cases</div>
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
        ) : <div className="empty"><span className="big">⌖</span>Upload a file from the Alerts or Investigations tab to begin.</div>}
      </div>
    </div>
  );
}
