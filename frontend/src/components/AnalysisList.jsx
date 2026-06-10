import React from "react";

export default function AnalysisList({ analyses, selectedId, onSelect, checked, onCheck }) {
  if (!analyses.length) return <div className="muted" style={{ fontSize: 13 }}>No analyses yet.</div>;

  const toggle = (id) =>
    onCheck(checked.includes(id) ? checked.filter((c) => c !== id) : [...checked, id]);

  return (
    <div>
      {analyses.map((a) => (
        <div
          key={a.id}
          className={`analysis-item ${a.id === selectedId ? "active" : ""}`}
          onClick={() => a.status === "completed" && onSelect(a.id)}
        >
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={checked.includes(a.id)}
              disabled={a.status !== "completed"}
              onClick={(e) => e.stopPropagation()}
              onChange={() => toggle(a.id)}
            />
            <div>
              <div className="name">{a.filename}</div>
              <div className="meta">{a.module}{a.score != null ? ` · score ${a.score}` : ""}</div>
            </div>
          </div>
          <span className={`badge ${a.status === "completed" ? a.severity : a.status}`}>
            {a.status === "completed" ? a.severity : a.status}
          </span>
        </div>
      ))}
    </div>
  );
}
