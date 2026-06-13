import React, { useState } from "react";
import { explainFinding } from "../api/client.js";

export default function Findings({ findings, analysisId }) {
  if (!findings?.length) return <div className="muted">No findings.</div>;
  return (
    <div>
      {findings.map((f, i) => (
        <FindingCard key={i} f={f} index={i} analysisId={analysisId} />
      ))}
    </div>
  );
}

function FindingCard({ f, index, analysisId }) {
  const [state, setState] = useState("idle"); // idle | loading | done | error
  const [explanation, setExplanation] = useState("");
  const [open, setOpen] = useState(false);

  const explain = async () => {
    if (explanation) { setOpen((o) => !o); return; }
    setState("loading");
    try {
      const res = await explainFinding(analysisId, index);
      setExplanation(res.explanation || "No explanation returned.");
      setState("done");
      setOpen(true);
    } catch (e) {
      setExplanation(`Could not generate explanation: ${e.message}`);
      setState("error");
      setOpen(true);
    }
  };

  return (
    <div className={`finding ${f.severity}`}>
      <h3>
        {f.title}
        <span className={`badge ${f.severity}`}>{f.severity}</span>
        <span className="conf">CONF {(f.confidence * 100).toFixed(0)}%</span>
        {analysisId && (
          <button className="btn sm explain-btn" onClick={explain} disabled={state === "loading"}>
            {state === "loading" ? "Thinking…" : open ? "Hide" : "✦ Explain"}
          </button>
        )}
      </h3>
      <p>{f.description}</p>
      {f.mitre_techniques?.length > 0 && (
        <div className="mitre-tags">
          {f.mitre_techniques.map((t) => <span key={t} className="mitre-tag">{t}</span>)}
        </div>
      )}
      {f.remediation?.length > 0 && (
        <ul>{f.remediation.map((r, j) => <li key={j}>{r}</li>)}</ul>
      )}
      {open && explanation && (
        <div className={`explain-box ${state === "error" ? "err" : ""}`}>
          {explanation.split("\n").map((line, k) =>
            line.trim() === "" ? <br key={k} /> : <p key={k}>{line}</p>
          )}
        </div>
      )}
    </div>
  );
}
