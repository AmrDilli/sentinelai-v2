import React, { useState } from "react";
import { approveAction } from "../api/client.js";

export default function SoarPanel({ apiId, actions, onChanged }) {
  const [busy, setBusy] = useState(-1);

  const approve = async (i) => {
    setBusy(i);
    try {
      await approveAction(apiId, i);
      onChanged?.();
    } finally {
      setBusy(-1);
    }
  };

  if (!actions?.length) return <div className="muted">No response actions.</div>;
  return (
    <div>
      {actions.map((a, i) => (
        <div key={i} className="soar-action">
          <div>
            <div className="what">
              {a.action.replaceAll("_", " ")} → <code>{a.target}</code>
            </div>
            <div className="why">{a.reason} · tier: {a.tier.replaceAll("_", " ")}</div>
          </div>
          {a.status === "pending approval" ? (
            <button className="primary" disabled={busy === i} onClick={() => approve(i)}>
              {busy === i ? "…" : "Approve"}
            </button>
          ) : (
            <span className={`status-pill ${a.status.startsWith("executed") ? "executed" : "pending"}`}>
              {a.status}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
