import React from "react";
import ReportView from "../components/ReportView.jsx";
import { IconNetwork, IconChip, IconCloud } from "../components/icons.jsx";

const MOD_ICON = { network: IconNetwork, forensics: IconCloud, malware: IconChip };

// Focused, single-artifact view (no ingest panel, no case queue) opened from an
// alert / dashboard / search. Hidden from the sidebar — reached only by drill-in.
export default function CasePage({ report, onBack, onChanged }) {
  if (!report) return <div className="card empty"><span className="big">⌖</span>Loading case…</div>;
  const Mod = MOD_ICON[report.module] || IconChip;
  const sev = report.report?.severity || report.severity;

  return (
    <div className="view-enter">
      <div className="case-head">
        <button className="btn sm case-back" onClick={onBack}>‹ Back</button>
        <div className="case-title">
          <span className="case-file"><Mod size={15} /> {report.filename}</span>
          {sev && <span className={`badge ${sev}`}>{sev}</span>}
        </div>
        {report.case_number && <span className="case-num">{report.case_number}</span>}
      </div>
      <ReportView analysis={report} onChanged={onChanged} />
    </div>
  );
}
