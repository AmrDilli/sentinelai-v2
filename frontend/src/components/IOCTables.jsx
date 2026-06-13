import React, { useState } from "react";

const GROUPS = [
  ["ips", "IP Addresses"],
  ["domains", "Domains"],
  ["urls", "URLs"],
  ["hashes", "File Hashes"],
  ["accounts", "Accounts"],
];

export default function IOCTables({ iocs, reputation }) {
  const present = GROUPS.filter(([k]) => (iocs?.[k] || []).length > 0);
  if (!present.length) return <div className="muted">No indicators of compromise extracted.</div>;
  return (
    <div className="ioc-tables">
      {present.map(([key, label]) => (
        <IOCGroup key={key} label={label} items={iocs[key]}
          reputation={key === "ips" ? reputation : null} />
      ))}
    </div>
  );
}

function IOCGroup({ label, items, reputation }) {
  const [open, setOpen] = useState(items.length <= 8);
  const copy = (e, text) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(text);
  };
  return (
    <div className="ioc-group">
      <div className="ioc-head" onClick={() => setOpen(!open)}>
        <span>{open ? "▾" : "▸"} {label}</span>
        <span className="ioc-count">{items.length}</span>
      </div>
      {open && (
        <div className="ioc-list">
          {items.map((it) => {
            const conf = reputation?.[it]?.abuse_confidence || 0;
            return (
              <div key={it} className="ioc-row" onClick={(e) => copy(e, it)} title="Click to copy">
                <code>{it}</code>
                {conf >= 50 && <span className="ioc-flag">{conf}% abuse</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
