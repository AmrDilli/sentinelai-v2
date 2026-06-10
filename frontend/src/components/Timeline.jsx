import React from "react";

export default function Timeline({ events }) {
  if (!events?.length) return <div className="muted">No timeline events.</div>;
  return (
    <div className="timeline">
      {events.map((e, i) => (
        <div key={i} className="tl-event">
          <span className="ts">{(e.timestamp || "").replace("T", " ").slice(0, 19)}</span>
          <span className="tl-line">
            <span className={`tl-dot ${e.severity}`} />
          </span>
          <span>
            <strong>{e.event}</strong>
            {e.detail ? <span className="muted"> — {e.detail}</span> : null}
          </span>
        </div>
      ))}
    </div>
  );
}
