import React from "react";
import { exportJSON, exportPDF } from "../api/export.js";
import { IconReport } from "../components/icons.jsx";

const SEV_COLOR = { info: "#64748b", low: "#38bdf8", medium: "#f59e0b", high: "#f97316", critical: "#ef4444" };

export default function ReportsPage({ analyses, onOpen }) {
  const done = analyses.filter((a) => a.status === "completed" && a.report);
  return (
    <div className="view-enter">
      <div className="page-head"><h1>Reports</h1>
        <span className="sub">Export completed investigations</span></div>

      {!done.length ? (
        <div className="card empty"><span className="big"><IconReport size={34} /></span>No completed reports yet.</div>
      ) : (
        <div className="card">
          <table className="tbl">
            <thead><tr><th>Artifact</th><th>Module</th><th>Severity</th><th>Score</th><th>Findings</th><th>Generated</th><th>Export</th></tr></thead>
            <tbody>
              {done.map((a) => (
                <tr key={a.id}>
                  <td style={{ cursor: "pointer" }} onClick={() => onOpen(a.id)}>{a.filename}</td>
                  <td className="dim" style={{ textTransform: "uppercase", fontSize: 11 }}>{a.module}</td>
                  <td><span className={`badge ${a.severity}`}>{a.severity}</span></td>
                  <td style={{ color: SEV_COLOR[a.severity], fontWeight: 700 }}>{a.report.score}</td>
                  <td>{a.report.findings.length}</td>
                  <td className="dim" style={{ fontSize: 12 }}>{(a.report.generated_at || "").replace("T", " ").slice(0, 16)}</td>
                  <td>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button className="btn sm" onClick={() => exportJSON(a.report)}>JSON</button>
                      <button className="btn sm" onClick={() => exportPDF(a.report)}>PDF</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
