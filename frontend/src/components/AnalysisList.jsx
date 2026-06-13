import React from "react";
import { deleteAnalysis } from "../api/client.js";

export default function AnalysisList({ analyses, selectedId, onSelect, checked, onCheck, onDeleted, toast }) {
  if (!analyses.length) return <div className="muted" style={{ fontSize: 12 }}>No cases yet.</div>;

  const toggle = (id) =>
    onCheck(checked.includes(id) ? checked.filter((c) => c !== id) : [...checked, id]);

  const remove = async (e, id) => {
    e.stopPropagation();
    await deleteAnalysis(id);
    toast?.("Case removed", "info");
    onDeleted?.(id);
  };

  return (
    <div>
      {analyses.map((a) => (
        <div
          key={a.id}
          className={`analysis-item ${a.id === selectedId ? "active" : ""}`}
          onClick={() => a.status === "completed" && onSelect(a.id)}
        >
          <div style={{ display: "flex", gap: 8, alignItems: "center", minWidth: 0 }}>
            <input
              type="checkbox"
              checked={checked.includes(a.id)}
              disabled={a.status !== "completed"}
              onClick={(e) => e.stopPropagation()}
              onChange={() => toggle(a.id)}
            />
            <div style={{ minWidth: 0 }}>
              <div className="name">{a.filename}</div>
              <div className="meta">
                {a.module}{a.score != null ? ` · score ${a.score}` : ""}
              </div>
              {a.status === "running" && (
                <div className="mini-progress">
                  <div className="mini-bar" style={{ width: `${a.progress || 0}%` }} />
                </div>
              )}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span className={`badge ${a.status === "completed" ? a.severity : a.status}`}>
              {a.status === "completed" ? a.severity : a.status === "running" ? `${a.progress || 0}%` : a.status}
            </span>
            <button className="icon-btn" title="Delete" onClick={(e) => remove(e, a.id)}>✕</button>
          </div>
        </div>
      ))}
    </div>
  );
}
