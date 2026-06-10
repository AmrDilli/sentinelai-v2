import React from "react";

export default function Findings({ findings }) {
  if (!findings?.length) return <div className="muted">No findings.</div>;
  return (
    <div>
      {findings.map((f, i) => (
        <div key={i} className={`finding ${f.severity}`}>
          <h3>
            {f.title}
            <span className={`badge ${f.severity}`}>{f.severity}</span>
            <span className="conf">CONF {(f.confidence * 100).toFixed(0)}%</span>
          </h3>
          <p>{f.description}</p>
          {f.mitre_techniques?.length > 0 && (
            <div className="mitre-tags">
              {f.mitre_techniques.map((t) => <span key={t} className="mitre-tag">{t}</span>)}
            </div>
          )}
          {f.remediation?.length > 0 && (
            <ul>{f.remediation.map((r, j) => <li key={j}>{r}</li>)}</ul>
          )}
        </div>
      ))}
    </div>
  );
}
