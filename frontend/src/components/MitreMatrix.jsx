import React from "react";

export default function MitreMatrix({ matrix }) {
  if (!matrix?.length) return <div className="muted">No MITRE ATT&amp;CK mappings.</div>;
  return (
    <div className="mitre-grid">
      {matrix.map((t) => (
        <div key={t.tactic_id} className="mitre-tactic">
          <h4>{t.tactic_name} <code>{t.tactic_id}</code></h4>
          {t.techniques.map((tech) => (
            <div key={tech.id} className="tech">
              <code>{tech.id}</code> {tech.name}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
