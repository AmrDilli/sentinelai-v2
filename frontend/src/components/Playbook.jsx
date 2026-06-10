import React from "react";

export default function Playbook({ steps }) {
  if (!steps?.length) return <div className="muted">No playbook generated.</div>;
  return (
    <div>
      {steps.map((s) => (
        <div key={s.step} className="pb-step">
          <div className="pb-num">{s.step}</div>
          <div className="pb-body">
            <span className="phase">{s.phase}</span>
            <h4>{s.title}</h4>
            <p>{s.instructions}</p>
            {s.expected_outcome && <div className="outcome">Expected: {s.expected_outcome}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}
