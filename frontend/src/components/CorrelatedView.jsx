import React from "react";
import ScoreGauge from "./ScoreGauge.jsx";
import SeverityChart from "./SeverityChart.jsx";
import MitreMatrix from "./MitreMatrix.jsx";
import Playbook from "./Playbook.jsx";

export default function CorrelatedView({ data }) {
  return (
    <div className="report-grid">
      <div className="panel full">
        <h2>Unified Investigation — {data.source_files.join(" + ")}</h2>
        <div className="score-row">
          <ScoreGauge score={data.score} severity={data.severity} />
          <div className="overview-meta">
            <span className={`badge ${data.severity}`}>{data.severity}</span>
            <span className="kv">MODULES <b style={{ textTransform: "uppercase" }}>{data.modules.join(" · ")}</b></span>
            <span className="kv">COMBINED SCORE <b>{data.score}/100</b></span>
          </div>
        </div>
        {Object.entries(data.narratives).map(([mod, n]) => (
          <p key={mod} className="narrative">
            <strong style={{ textTransform: "uppercase", color: "#22d3ee" }}>{mod}</strong> — {n}
          </p>
        ))}
      </div>
      <div className="panel">
        <h2>Combined Severity</h2>
        <SeverityChart distribution={data.severity_distribution} />
      </div>
      <div className="panel">
        <h2>Combined MITRE ATT&amp;CK</h2>
        <MitreMatrix matrix={data.mitre} />
      </div>
      <div className="panel full">
        <h2>Unified Cross-Module Playbook</h2>
        <Playbook steps={data.playbook} />
      </div>
    </div>
  );
}
