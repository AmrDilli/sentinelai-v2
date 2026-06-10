import React, { useEffect, useState, useCallback } from "react";
import { listAnalyses, getAnalysis, correlate } from "./api/client.js";
import UploadPanel from "./components/UploadPanel.jsx";
import AnalysisList from "./components/AnalysisList.jsx";
import ReportView from "./components/ReportView.jsx";
import CorrelatedView from "./components/CorrelatedView.jsx";

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="clock">{now.toISOString().slice(0, 19).replace("T", " ")} UTC</span>;
}

export default function App() {
  const [analyses, setAnalyses] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [report, setReport] = useState(null);
  const [checked, setChecked] = useState([]);
  const [correlated, setCorrelated] = useState(null);
  const [error, setError] = useState("");
  const [health, setHealth] = useState(null);

  const refresh = useCallback(async () => {
    try {
      setAnalyses(await listAnalyses());
    } catch {
      /* backend not up yet */
    }
  }, []);

  useEffect(() => {
    refresh();
    fetch("/api/health").then((r) => r.json()).then(setHealth).catch(() => {});
    const t = setInterval(refresh, 2500);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    if (!selectedId) return;
    setCorrelated(null);
    getAnalysis(selectedId).then(setReport).catch(() => setReport(null));
  }, [selectedId, analyses]);

  const runCorrelation = async () => {
    setError("");
    try {
      setCorrelated(await correlate(checked));
      setReport(null);
      setSelectedId(null);
    } catch (e) {
      setError(e.message);
    }
  };

  const running = analyses.some((a) => a.status === "running");

  return (
    <div className="app">
      <div className="header">
        <h1>Sentinel<span>AI</span></h1>
        <span className="tag">v2 · Triage &amp; Response Console</span>
        <div className="spacer" />
        <div className="statuslight">
          <span className={`dot ${health ? "" : "off"}`} />
          {health ? `Engine: ${health.ai_provider}` : "Backend offline"}
        </div>
        <div className="statuslight">
          <span className={`dot ${running ? "" : "off"}`} />
          {running ? "Analyzing" : "Idle"}
        </div>
        <Clock />
      </div>

      <div className="layout">
        <div>
          <UploadPanel onUploaded={refresh} />
          <div className="panel" style={{ marginTop: 16 }}>
            <h2>Case Queue</h2>
            <AnalysisList
              analyses={analyses}
              selectedId={selectedId}
              onSelect={setSelectedId}
              checked={checked}
              onCheck={setChecked}
            />
            {checked.length >= 2 && (
              <div className="correlate-bar">
                <button className="primary" onClick={runCorrelation}>
                  Correlate {checked.length} cases
                </button>
              </div>
            )}
            {error && <div className="error-box" style={{ marginTop: 8 }}>{error}</div>}
          </div>
        </div>
        <div>
          {correlated ? (
            <CorrelatedView data={correlated} />
          ) : report ? (
            <ReportView analysis={report} onChanged={() => getAnalysis(selectedId).then(setReport)} />
          ) : (
            <div className="panel empty">
              <span className="big">⌖</span>
              AWAITING ARTIFACT
              <br />
              Drop a PCAP, Windows event log (.evtx / .xml / .jsonl), or suspicious
              file to open a case. Select a case from the queue to view its report.
              Check 2+ cases to build a unified cross-module investigation.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
