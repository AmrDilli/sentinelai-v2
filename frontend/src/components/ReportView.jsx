import React from "react";
import ScoreGauge from "./ScoreGauge.jsx";
import SeverityChart from "./SeverityChart.jsx";
import StatsCharts from "./StatsCharts.jsx";
import Findings from "./Findings.jsx";
import Timeline from "./Timeline.jsx";
import MitreMatrix from "./MitreMatrix.jsx";
import Playbook from "./Playbook.jsx";
import SoarPanel from "./SoarPanel.jsx";
import GeoMap from "./GeoMap.jsx";
import IOCTables from "./IOCTables.jsx";
import { exportJSON, exportServerPDF } from "../api/export.js";

export default function ReportView({ analysis, onChanged }) {
  if (analysis.status === "failed") {
    return <div className="card"><div className="card-title">Analysis failed</div><div className="error-box">{analysis.error}</div></div>;
  }
  if (analysis.status !== "completed") {
    return (
      <div className="card">
        <div className="scan-running">
          {analysis.stage || "Deep scan in progress"}
          <div className="bar" />
          <div style={{ marginTop: 10, fontSize: 20 }}>{analysis.progress || 0}%</div>
        </div>
      </div>
    );
  }

  const r = analysis.report;
  const enr = r.summary.enrichment || {};
  const usage = r.usage || {};

  return (
    <div className="report-grid stagger">
      <div className="card full">
        <div className="card-title">
          Threat Overview
          <span className="h2-actions">
            <button className="btn sm" onClick={() => exportJSON(r)}>⤓ JSON</button>
            <button className="btn sm" onClick={() => exportServerPDF(analysis.id, r)}>⤓ PDF</button>
          </span>
        </div>
        <div className="overview-flex">
          <ScoreGauge score={r.score} severity={r.severity} />
          <div className="overview-meta">
            <span className={`badge ${r.severity}`}>{r.severity}</span>
            <span className="kv">ARTIFACT <b>{r.source_file}</b></span>
            <span className="kv">MODULE <b style={{ textTransform: "uppercase" }}>{r.module}</b></span>
            <span className="kv">ENGINE <b>{r.ai_provider}{r.cached ? " (cached)" : ""}</b></span>
            <span className="kv">FINDINGS <b>{r.findings.length}</b></span>
            {usage.cost_usd > 0 && (
              <span className="kv">AI COST <b>${usage.cost_usd.toFixed(4)}</b>
                <span className="muted"> · {usage.prompt_tokens + usage.completion_tokens} tok</span></span>
            )}
          </div>
          <p className="narrative" style={{ flex: 1, minWidth: 240 }}>{r.narrative}</p>
        </div>
      </div>

      <div className="card"><div className="card-title">Severity Distribution</div>
        <SeverityChart distribution={r.severity_distribution} /></div>

      <div className="card"><div className="card-title">Telemetry</div>
        <StatsCharts summary={r.summary} /></div>

      <div className="card full"><div className="card-title">Findings</div>
        <Findings findings={r.findings} analysisId={analysis.id} /></div>

      {r.module === "network" && (
        <div className="card full"><div className="card-title">Connection Geography</div>
          <GeoMap geo={enr.ip_geolocation} reputation={enr.ip_reputation} /></div>
      )}

      <div className="card"><div className="card-title">Activity Timeline</div>
        <Timeline events={r.summary.timeline} /></div>

      <div className="card"><div className="card-title">Indicators of Compromise</div>
        <IOCTables iocs={r.summary.iocs} reputation={enr.ip_reputation} /></div>

      <div className="card full"><div className="card-title">MITRE ATT&amp;CK Coverage</div>
        <MitreMatrix matrix={r.mitre} /></div>

      <div className="card full"><div className="card-title">Investigation Playbook</div>
        <Playbook steps={r.playbook} /></div>

      <div className="card full"><div className="card-title">Automated Response · SOAR</div>
        <SoarPanel apiId={analysis.id} actions={r.soar_actions} onChanged={onChanged} /></div>
    </div>
  );
}
