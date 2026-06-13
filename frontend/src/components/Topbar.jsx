import React from "react";
import { IconPulse, IconBell, IconUser, IconSearch } from "./icons.jsx";

// Derive a global threat level from the worst severity across analyses.
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function worstSeverity(analyses) {
  let worst = "info";
  for (const a of analyses) {
    if (a.severity && RANK[a.severity] > RANK[worst]) worst = a.severity;
  }
  return worst;
}

export default function Topbar({ analyses, backendUp, timeFilter, setTimeFilter, user, onLogout }) {
  const threat = worstSeverity(analyses.filter((a) => a.status === "completed"));
  const threatClass = ["high", "critical"].includes(threat) ? "crit" : threat === "medium" ? "warn" : "ok";
  const running = analyses.some((a) => a.status === "running");
  const alertCount = analyses.filter((a) => a.status === "completed").length;

  return (
    <header className="topbar">
      <div className="tb-stat">
        <IconPulse size={18} />
        System Health:
        <span className={`pill ${backendUp ? "ok" : "crit"}`}>{backendUp ? "OPERATIONAL" : "OFFLINE"}</span>
      </div>
      <div className="tb-stat">
        <IconPulse size={18} />
        Threat Level:
        <span className={`pill ${threatClass}`}>{threat.toUpperCase()}</span>
      </div>
      {running && <div className="tb-stat dim">● analyzing…</div>}

      <div className="tb-spacer" />

      <button className="tb-search" onClick={() => window.dispatchEvent(new CustomEvent("open-cmdk"))}>
        <IconSearch size={15} /> <span>Search</span> <kbd>⌘K</kbd>
      </button>

      <select className="tb-select" value={timeFilter} onChange={(e) => setTimeFilter(e.target.value)}>
        <option>All Time</option>
        <option>Last 24 Hours</option>
        <option>Last 7 Days</option>
      </select>

      <div className="tb-icon">
        <IconBell size={19} />
        {alertCount > 0 && <span className="tb-badge">{alertCount > 9 ? "9+" : alertCount}</span>}
      </div>

      <div className="tb-user">
        <div className="who">
          <b>{user?.username || "Analyst"}</b>
          <span>SOC Console · <a className="logout-link" onClick={onLogout}>Sign out</a></span>
        </div>
        <div className="tb-avatar">{(user?.username || "A").slice(0, 1).toUpperCase()}</div>
      </div>
    </header>
  );
}
