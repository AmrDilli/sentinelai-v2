import React from "react";
import ScoreGauge from "./ScoreGauge.jsx";
import SeverityChart from "./SeverityChart.jsx";
import Findings from "./Findings.jsx";
import Timeline from "./Timeline.jsx";
import MitreMatrix from "./MitreMatrix.jsx";
import Playbook from "./Playbook.jsx";
import SoarPanel from "./SoarPanel.jsx";

export default function ReportView({ analysis, onChanged }) {
  if (analysis.status === "failed") {
    return (
      <div className="panel">
        <h2>Analysis failed</h2>
        <div className="error-box">{analysis.error}</div>
      </div>
    );
  }
  if (analysis.status !== "completed") {
    return (
      <div className="panel">
        <div className="scan-running">
          Deep scan in progress
          <div className="bar" />
        </div>
      </div>
    );
  }

  const r = analysis.report;
  return (
    <div className="report-grid">
      <div className="panel">
        <h2>Threat Overview</h2>
        <div className="score-row">
          <ScoreGauge score={r.score} severity={r.severity} />
          <div className="overview-meta">
            <span className={`badge ${r.severity}`}>{r.severity}</span>
            <span className="kv">ARTIFACT <b>{r.source_file}</b></span>
            <span className="kv">MODULE <b style={{ textTransform: "uppercase" }}>{r.module}</b></span>
            <span className="kv">ENGINE <b>{r.ai_provider}</b></span>
            <span className="kv">FINDINGS <b>{r.findings.length}</b></span>
          </div>
        </div>
        <p className="narrative">{r.narrative}</p>
      </div>

      <div className="panel">
        <h2>Severity Distribution</h2>
        <SeverityChart distribution={r.severity_distribution} />
      </div>

      <div className="panel full">
        <h2>Findings</h2>
        <Findings findings={r.findings} />
      </div>

      <div className="panel">
        <h2>Activity Timeline</h2>
        <Timeline events={r.summary.timeline} />
      </div>

      <div className="panel">
        <h2>MITRE ATT&amp;CK Coverage</h2>
        <MitreMatrix matrix={r.mitre} />
      </div>

      <div className="panel full">
        <h2>Investigation Playbook</h2>
        <Playbook steps={r.playbook} />
      </div>

      <div className="panel full">
        <h2>Automated Response · SOAR</h2>
        <SoarPanel apiId={analysis.id} actions={r.soar_actions} onChanged={onChanged} />
      </div>
    </div>
  );
}
