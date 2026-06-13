import React from "react";
import ScoreGauge from "./ScoreGauge.jsx";
import SeverityChart from "./SeverityChart.jsx";
import MitreMatrix from "./MitreMatrix.jsx";
import Playbook from "./Playbook.jsx";

export default function CorrelatedView({ data }) {
  return (
    <div className="report-grid stagger">
      <div className="card full">
        <div className="card-title">Unified Investigation — {data.source_files.join(" + ")}</div>
        <div className="overview-flex">
          <ScoreGauge score={data.score} severity={data.severity} />
          <div className="overview-meta">
            <span className={`badge ${data.severity}`}>{data.severity}</span>
            <span className="kv">MODULES <b style={{ textTransform: "uppercase" }}>{data.modules.join(" · ")}</b></span>
            <span className="kv">COMBINED SCORE <b>{data.score}/100</b></span>
          </div>
        </div>
        {Object.entries(data.narratives).map(([mod, n]) => (
          <p key={mod} className="narrative" style={{ marginTop: 10 }}>
            <strong style={{ textTransform: "uppercase", color: "var(--brand)" }}>{mod}</strong> — {n}
          </p>
        ))}
      </div>
      <div className="card"><div className="card-title">Combined Severity</div>
        <SeverityChart distribution={data.severity_distribution} /></div>
      <div className="card"><div className="card-title">Combined MITRE ATT&amp;CK</div>
        <MitreMatrix matrix={data.mitre} /></div>
      <div className="card full"><div className="card-title">Unified Cross-Module Playbook</div>
        <Playbook steps={data.playbook} /></div>
    </div>
  );
}
