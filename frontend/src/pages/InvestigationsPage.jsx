import React from "react";
import ReportView from "../components/ReportView.jsx";
import CorrelatedView from "../components/CorrelatedView.jsx";
import UploadPanel from "../components/UploadPanel.jsx";
import { deleteAnalysis } from "../api/client.js";

const SEV_COLOR = { info: "#2dd4bf", low: "#facc15", medium: "#fb923c", high: "#ef5b15", critical: "#ef4444" };

export default function InvestigationsPage({
  analyses, selectedId, report, correlated, checked,
  onSelect, onCheck, onCorrelate, onUploaded, onChanged, onDeleted, toast,
}) {
  const remove = async (e, id) => {
    e.stopPropagation();
    await deleteAnalysis(id);
    toast?.("Case removed", "info");
    onDeleted?.(id);
  };
  const toggle = (id) => onCheck(checked.includes(id) ? checked.filter((c) => c !== id) : [...checked, id]);

  return (
    <div className="view-enter">
      <div className="page-head"><h1>Investigations</h1>
        <span className="sub">Case workspace — upload artifacts, open a case for its full report, or select 2+ to correlate · {analyses.length} case{analyses.length === 1 ? "" : "s"}</span></div>

      <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 16, alignItems: "start" }}>
        <div>
          <UploadPanel onUploaded={onUploaded} toast={toast} />
          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-title">Case Queue</div>
            {!analyses.length && <div className="muted" style={{ fontSize: 13 }}>No cases yet.</div>}
            {analyses.map((a) => (
              <div key={a.id} className="rrow" style={{ cursor: a.status === "completed" ? "pointer" : "default" }}
                onClick={() => a.status === "completed" && onSelect(a.id)}>
                <input type="checkbox" checked={checked.includes(a.id)} disabled={a.status !== "completed"}
                  onClick={(e) => e.stopPropagation()} onChange={() => toggle(a.id)}
                  style={{ accentColor: "var(--brand)" }} />
                <span className="dot" style={{ background: a.status === "completed" ? SEV_COLOR[a.severity] : "var(--brand)" }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="nm" style={{ fontSize: 13 }}>{a.filename}</div>
                  <div className="muted" style={{ fontSize: 11 }}>
                    {a.module}{a.score != null ? ` · ${a.score}` : ""}
                  </div>
                  {a.status === "running" && (
                    <div className="mini-progress"><div className="mini-bar" style={{ width: `${a.progress || 0}%` }} /></div>
                  )}
                </div>
                <span className={`badge ${a.status === "completed" ? a.severity : a.status}`}>
                  {a.status === "completed" ? a.severity : a.status === "running" ? `${a.progress || 0}%` : a.status}
                </span>
                <button className="btn sm" style={{ padding: "3px 7px" }} onClick={(e) => remove(e, a.id)}>✕</button>
              </div>
            ))}
            {checked.length >= 2 && (
              <button className="btn primary" style={{ width: "100%", marginTop: 12 }} onClick={onCorrelate}>
                Correlate {checked.length} cases
              </button>
            )}
          </div>
        </div>

        <div>
          {correlated ? <CorrelatedView data={correlated} />
            : report ? <ReportView analysis={report} onChanged={onChanged} />
            : <div className="card empty"><span className="big">⌖</span>
                Select a case from the queue to view its full investigation, or check 2+ cases to build a unified cross-module view.</div>}
        </div>
      </div>
    </div>
  );
}
