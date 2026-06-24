import React, { useEffect, useState } from "react";
import { listWatchlist, addWatchlist, removeWatchlist } from "../api/client.js";

const SEV_COLOR = { info: "#2dd4bf", low: "#facc15", medium: "#fb923c", high: "#ef5b15", critical: "#dc2626" };

export default function WatchlistPanel({ toast }) {
  const [items, setItems] = useState([]);
  const [type, setType] = useState("ip");
  const [value, setValue] = useState("");
  const [severity, setSeverity] = useState("high");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => listWatchlist().then(setItems).catch(() => {});
  useEffect(() => { load(); }, []);

  const add = async () => {
    if (!value.trim()) return;
    setBusy(true);
    try {
      await addWatchlist({ type, value: value.trim(), severity, note });
      setValue(""); setNote("");
      toast?.("Indicator added to watchlist", "info");
      load();
    } catch (e) { toast?.(e.message, "critical"); }
    finally { setBusy(false); }
  };

  const remove = async (id) => {
    try { await removeWatchlist(id); load(); } catch (e) { toast?.(e.message, "critical"); }
  };

  return (
    <div className="card" style={{ marginTop: 24 }}>
      <div className="card-title">IOC Watchlist
        <span className="muted" style={{ fontSize: 12, marginLeft: 8, fontWeight: 400 }}>
          your own known-bad indicators — matched on every analysis &amp; live window
        </span>
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 14 }}>
        <select className="tb-select" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="hash">File hash</option>
        </select>
        <input className="tb-input" placeholder={type === "hash" ? "sha256…" : type === "domain" ? "evil.example.com" : "45.133.1.99"}
          value={value} onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()} style={{ flex: 1, minWidth: 200 }} />
        <select className="tb-select" value={severity} onChange={(e) => setSeverity(e.target.value)} title="Severity if matched">
          <option value="medium">medium</option>
          <option value="high">high</option>
          <option value="critical">critical</option>
        </select>
        <input className="tb-input" placeholder="note (optional)" value={note}
          onChange={(e) => setNote(e.target.value)} style={{ width: 160 }} />
        <button className="btn primary" onClick={add} disabled={busy || !value.trim()}>Add</button>
      </div>

      {items.length ? (
        <div className="rlist">
          {items.map((it) => (
            <div key={it.id} className="rrow">
              <span className="ind-type">{it.type}</span>
              <code className="nm ind-code">{it.value}</code>
              <span className="badge" style={{ color: SEV_COLOR[it.severity], borderColor: SEV_COLOR[it.severity] }}>{it.severity}</span>
              {it.note && <span className="muted" style={{ fontSize: 12 }}>{it.note}</span>}
              <button className="btn sm" style={{ marginLeft: "auto" }} onClick={() => remove(it.id)}>✕</button>
            </div>
          ))}
        </div>
      ) : <div className="muted" style={{ fontSize: 13 }}>No custom indicators yet. Add IPs, domains, or file hashes you want flagged everywhere.</div>}
    </div>
  );
}
