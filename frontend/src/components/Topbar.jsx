import React, { useState, useRef, useEffect } from "react";
import { IconPulse, IconBell, IconSearch } from "./icons.jsx";

const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
function worstSeverity(analyses) {
  let worst = "info";
  for (const a of analyses) {
    if (a.severity && RANK[a.severity] > RANK[worst]) worst = a.severity;
  }
  return worst;
}
function ago(iso) {
  if (!iso) return "";
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (Number.isNaN(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export default function Topbar({ analyses, backendUp, timeFilter, setTimeFilter, user, onLogout, onOpenCase, onViewAlerts }) {
  const completed = analyses.filter((a) => a.status === "completed");
  const threat = worstSeverity(completed);
  const threatClass = ["high", "critical"].includes(threat) ? "crit" : threat === "medium" ? "warn" : "ok";
  const running = analyses.some((a) => a.status === "running");

  const notifs = completed
    .filter((a) => ["high", "critical"].includes(a.severity))
    .sort((x, y) => (y.report?.generated_at || "").localeCompare(x.report?.generated_at || ""));
  const alertCount = notifs.length;

  const [open, setOpen] = useState(false);
  const bellRef = useRef(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e) => { if (bellRef.current && !bellRef.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  const openCase = (id) => { setOpen(false); onOpenCase?.(id); };

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

      <div className="tb-bell" ref={bellRef}>
        <div className={`tb-icon ${open ? "on" : ""}`} onClick={() => setOpen((o) => !o)}
          role="button" aria-label="Notifications">
          <IconBell size={19} />
          {alertCount > 0 && <span className="tb-badge">{alertCount > 9 ? "9+" : alertCount}</span>}
        </div>
        {open && (
          <div className="notif-pop">
            <div className="notif-head">Notifications <span className="muted">{alertCount} high / critical</span></div>
            <div className="notif-list">
              {notifs.length === 0 ? (
                <div className="notif-empty">No high or critical alerts. You're clear.</div>
              ) : notifs.slice(0, 8).map((a) => (
                <div key={a.id} className="notif-row" onClick={() => openCase(a.id)}>
                  <span className="dot" style={{ background: a.severity === "critical" ? "var(--critical)" : "var(--high)" }} />
                  <div className="notif-main">
                    <div className="notif-file">{a.case_number ? <code>{a.case_number}</code> : null} {a.filename}</div>
                    <div className="notif-sub"><span className={`badge ${a.severity}`}>{a.severity}</span> {ago(a.report?.generated_at)}</div>
                  </div>
                </div>
              ))}
            </div>
            <div className="notif-foot" onClick={() => { setOpen(false); onViewAlerts?.(); }}>View all alerts ›</div>
          </div>
        )}
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
