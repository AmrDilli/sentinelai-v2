import React from "react";

// Full enterprise kill-chain order so the strip reads left-to-right like ATT&CK.
const KILL_CHAIN = [
  ["TA0001", "Initial Access"], ["TA0002", "Execution"], ["TA0003", "Persistence"],
  ["TA0004", "Priv. Esc"], ["TA0005", "Defense Evasion"], ["TA0006", "Cred. Access"],
  ["TA0007", "Discovery"], ["TA0008", "Lateral Move"], ["TA0009", "Collection"],
  ["TA0011", "C2"], ["TA0010", "Exfiltration"], ["TA0040", "Impact"],
];

export default function MitreMatrix({ matrix }) {
  if (!matrix?.length) return <div className="muted">No MITRE ATT&amp;CK mappings.</div>;
  const byTactic = Object.fromEntries(matrix.map((t) => [t.tactic_id, t]));
  const maxTech = Math.max(1, ...matrix.map((t) => t.techniques.length));
  const activeTactics = KILL_CHAIN.filter(([id]) => byTactic[id]);

  return (
    <div className="attack-wrap">
      {/* Kill-chain strip: every tactic, lit where there's activity */}
      <div className="kc-strip">
        {KILL_CHAIN.map(([id, name], i) => {
          const hit = byTactic[id];
          const count = hit ? hit.techniques.length : 0;
          const intensity = count / maxTech;
          return (
            <React.Fragment key={id}>
              <div className={`kc-stage ${count ? "lit" : ""}`}
                style={count ? { background: `rgba(244,63,94,${0.22 + intensity * 0.55})` } : {}}
                title={`${name}${count ? ` — ${count} technique${count > 1 ? "s" : ""}` : " — no activity"}`}>
                <span className="kc-name">{name}</span>
                {count > 0 && <span className="kc-badge">{count}</span>}
              </div>
              {i < KILL_CHAIN.length - 1 && <span className={`kc-arrow ${count ? "lit" : ""}`}>›</span>}
            </React.Fragment>
          );
        })}
      </div>

      {/* Detail cards: only tactics that actually fired, with deduped techniques */}
      <div className="kc-detail">
        {activeTactics.map(([id, name]) => {
          const hit = byTactic[id];
          return (
            <div key={id} className="kc-card">
              <div className="kc-card-head">
                <span>{name}</span>
                <code>{id}</code>
              </div>
              {hit.techniques.map((t) => (
                <div key={t.id} className="kc-tech" title={(t.findings || []).join("\n")}>
                  <code>{t.id}</code>
                  <span className="kc-tech-name">{t.name}</span>
                  {t.findings && t.findings.length > 1 && (
                    <span className="kc-tech-count">×{t.findings.length}</span>
                  )}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
