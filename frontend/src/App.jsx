import React, { useEffect, useState, useCallback, useRef, useMemo } from "react";
import { listAnalyses, getAnalysis, correlate, me, logout as apiLogout, getToken } from "./api/client.js";
import { useToast } from "./components/Toast.jsx";
import { useTheme } from "./useTheme.js";
import AuthScreen from "./components/AuthScreen.jsx";
import CommandPalette from "./components/CommandPalette.jsx";
import Sidebar from "./components/Sidebar.jsx";
import Topbar from "./components/Topbar.jsx";

const VIEWS = [
  { id: "dashboard", label: "Dashboard" }, { id: "alerts", label: "Alerts" },
  { id: "investigations", label: "Investigations" }, { id: "trends", label: "Trends" },
  { id: "reports", label: "Reports" }, { id: "settings", label: "Settings" },
];
// Global time-filter windows (used by the Topbar dropdown).
const TIME_WINDOWS_MS = { "Last 24 Hours": 24 * 3600e3, "Last 7 Days": 7 * 24 * 3600e3 };
function withinTimeWindow(analyses, filter) {
  const span = TIME_WINDOWS_MS[filter];
  if (!span) return analyses; // "All Time"
  const cutoff = Date.now() - span;
  return analyses.filter((a) => {
    if (a.status !== "completed") return true; // keep in-progress / failed visible
    const t = a.generated_at ? Date.parse(a.generated_at) : NaN;
    return Number.isNaN(t) || t >= cutoff;
  });
}

import DashboardPage from "./pages/DashboardPage.jsx";
import AlertsPage from "./pages/AlertsPage.jsx";
import InvestigationsPage from "./pages/InvestigationsPage.jsx";
import TrendsPage from "./pages/TrendsPage.jsx";
import ReportsPage from "./pages/ReportsPage.jsx";
import SettingsPage from "./pages/SettingsPage.jsx";
import LiveCapturePage from "./pages/LiveCapturePage.jsx";

export default function App() {
  const toast = useToast();
  const { theme, toggle } = useTheme();
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [view, setView] = useState("dashboard");
  const [mode, setMode] = useState("file"); // "file" | "live"
  const [analyses, setAnalyses] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [report, setReport] = useState(null);
  const [checked, setChecked] = useState([]);
  const [correlated, setCorrelated] = useState(null);
  const [health, setHealth] = useState(null);
  const [timeFilter, setTimeFilter] = useState("All Time");
  const seen = useRef({});

  // Restore session on load if a token exists. Never block the UI forever: if
  // the backend is down or slow to answer /auth/me, fall through to the auth
  // screen after a short timeout instead of spinning on "Loading…".
  useEffect(() => {
    if (!getToken()) { setAuthChecked(true); return; }
    let settled = false;
    const finish = () => { if (!settled) { settled = true; setAuthChecked(true); } };
    me().then(setUser).catch(() => setUser(null)).finally(finish);
    const t = setTimeout(finish, 6000);
    return () => clearTimeout(t);
  }, []);

  // Apply a fresh analyses list: fire status-change toasts, then store it.
  const applyList = useCallback((list) => {
    for (const a of list) {
      const prev = seen.current[a.id];
      if (prev && prev !== a.status) {
        if (a.status === "completed") {
          const sev = a.severity || "info";
          toast(`${a.filename}: ${sev.toUpperCase()} — analysis complete`,
            ["high", "critical"].includes(sev) ? "critical" : "success");
        } else if (a.status === "failed") {
          toast(`${a.filename}: analysis failed`, "critical");
        }
      }
      seen.current[a.id] = a.status;
    }
    setAnalyses(list);
  }, [toast]);

  const refresh = useCallback(async () => {
    try { applyList(await listAnalyses()); } catch { /* backend not up */ }
  }, [applyList]);

  useEffect(() => {
    if (!user) return;
    refresh();
    fetch("/api/health").then((r) => r.json()).then(setHealth).catch(() => {});

    // Prefer a live WebSocket stream; fall back to polling if it drops.
    let ws, poll = null, stopped = false;
    const startPolling = () => { if (!poll) poll = setInterval(refresh, 2500); };
    const stopPolling = () => { if (poll) { clearInterval(poll); poll = null; } };
    const connectWS = () => {
      if (stopped) return;
      try {
        const proto = location.protocol === "https:" ? "wss" : "ws";
        ws = new WebSocket(
          `${proto}://${location.host}/api/ws/analyses?token=${encodeURIComponent(getToken())}`);
        ws.onmessage = (e) => {
          try { const d = JSON.parse(e.data); if (d.analyses) { applyList(d.analyses); stopPolling(); } }
          catch { /* ignore malformed frame */ }
        };
        ws.onclose = () => { if (!stopped) { startPolling(); setTimeout(connectWS, 4000); } };
        ws.onerror = () => { try { ws.close(); } catch { /* noop */ } };
      } catch { startPolling(); }
    };
    startPolling();   // immediate fallback; WS clears it on first message
    connectWS();
    return () => { stopped = true; stopPolling(); try { ws && ws.close(); } catch { /* noop */ } };
  }, [refresh, applyList, user]);

  const handleLogout = async () => {
    await apiLogout();
    setUser(null); setAnalyses([]); setSelectedId(null); setReport(null);
    setChecked([]); setCorrelated(null); seen.current = {}; setView("dashboard");
    toast("Signed out", "info");
  };

  useEffect(() => {
    if (!selectedId) { setReport(null); return; }
    getAnalysis(selectedId).then(setReport).catch(() => setReport(null));
  }, [selectedId, analyses]);

  const openCase = (id) => { setCorrelated(null); setSelectedId(id); setView("investigations"); };

  const runCorrelation = async () => {
    try {
      setCorrelated(await correlate(checked));
      setReport(null); setSelectedId(null);
      toast(`Correlated ${checked.length} cases`, "success");
    } catch (e) { toast(e.message, "critical"); }
  };

  const onDeleted = (id) => {
    if (selectedId === id) { setSelectedId(null); setReport(null); }
    setChecked((c) => c.filter((x) => x !== id));
    refresh();
  };

  // Apply the global time filter to everything the aggregate views render.
  const visible = useMemo(() => withinTimeWindow(analyses, timeFilter), [analyses, timeFilter]);
  const alertCount = visible.filter((a) => a.status === "completed").length;

  if (!authChecked) return <div className="boot">Loading…</div>;
  if (!user) return <AuthScreen onAuthed={setUser} />;

  return (
    <div className="shell">
      <CommandPalette analyses={analyses} views={VIEWS} onOpen={openCase}
        setView={(v) => { setView(v); setCorrelated(null); }} />
      <Sidebar view={view} setView={(v) => { setView(v); setCorrelated(null); }}
        alertCount={alertCount} theme={theme} toggleTheme={toggle}
        mode={mode} setMode={setMode} />
      <div className="main">
        <Topbar analyses={visible} backendUp={!!health} timeFilter={timeFilter}
          setTimeFilter={setTimeFilter} user={user} onLogout={handleLogout} />
        <div className="content">
          {mode === "live" && <LiveCapturePage />}
          {mode === "file" && <>
          {view === "dashboard" && <DashboardPage analyses={visible} onOpen={openCase} />}
          {view === "alerts" && <AlertsPage analyses={visible} onOpen={openCase}
            onGoToInvestigations={() => { setView("investigations"); setCorrelated(null); }} />}
          {view === "investigations" && (
            <InvestigationsPage
              analyses={visible} selectedId={selectedId} report={report}
              correlated={correlated} checked={checked}
              onSelect={(id) => { setCorrelated(null); setSelectedId(id); }}
              onCheck={setChecked} onCorrelate={runCorrelation}
              onUploaded={refresh} onChanged={() => getAnalysis(selectedId).then(setReport)}
              onDeleted={onDeleted} toast={toast} />
          )}
          {view === "trends" && <TrendsPage analyses={visible} />}
          {view === "reports" && <ReportsPage analyses={visible} onOpen={openCase} />}
          {view === "settings" && <SettingsPage health={health} toast={toast} />}
          </>}
        </div>
      </div>
    </div>
  );
}
