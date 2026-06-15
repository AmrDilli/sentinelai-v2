import React from "react";
import {
  IconDashboard, IconAlert, IconSearch, IconTrend, IconReport,
  IconSettings, IconShield, IconSun, IconMoon,
} from "./icons.jsx";

const NAV = [
  { id: "dashboard", label: "Dashboard", Icon: IconDashboard },
  { id: "alerts", label: "Alerts", Icon: IconAlert },
  { id: "investigations", label: "Investigations", Icon: IconSearch },
  { id: "trends", label: "Trends", Icon: IconTrend },
  { id: "reports", label: "Reports", Icon: IconReport },
];

export default function Sidebar({ view, setView, alertCount, theme, toggleTheme, mode, setMode }) {
  const live = mode === "live";
  return (
    <aside className="sidebar">
      <div className="brand" onClick={() => { setMode("file"); setView("dashboard"); }}
        role="button" title="Go to dashboard" style={{ cursor: "pointer" }}>
        <div className="brand-logo"><IconShield size={22} /></div>
        <div className="brand-name">Sentinel<span>AI</span></div>
      </div>

      {/* Mode switch: File Analysis <-> Live Capture */}
      <div className="mode-switch">
        <button className={`mode-btn ${!live ? "on" : ""}`} onClick={() => setMode("file")}>
          <IconReport size={15} /> File
        </button>
        <button className={`mode-btn ${live ? "on" : ""}`} onClick={() => setMode("live")}>
          <span className="live-dot" /> Live
        </button>
      </div>

      <nav className="nav">
        {NAV.map(({ id, label, Icon }) => (
          <div key={id}
            className={`nav-item ${!live && view === id ? "active" : ""} ${live ? "muted-nav" : ""}`}
            onClick={() => { setMode("file"); setView(id); }}>
            <Icon />
            <span>{label}</span>
            {id === "alerts" && alertCount > 0 && <span className="nav-count">{alertCount}</span>}
          </div>
        ))}
      </nav>

      <div className="nav-spacer" />

      <nav className="nav">
        <div className={`nav-item ${!live && view === "settings" ? "active" : ""}`}
          onClick={() => { setMode("file"); setView("settings"); }}>
          <IconSettings /><span>Settings</span>
        </div>
      </nav>

      <div className={`theme-toggle ${theme}`} onClick={toggleTheme} title="Toggle light / dark">
        <div className="tt-knob"><span>{theme === "dark" ? <IconMoon size={14} /> : <IconSun size={14} />}</span></div>
        <span className="tt-ico sun"><IconSun size={14} /></span>
        <span className="tt-ico moon"><IconMoon size={14} /></span>
      </div>
    </aside>
  );
}
