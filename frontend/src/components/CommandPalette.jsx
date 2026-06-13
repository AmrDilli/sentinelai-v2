import React, { useEffect, useMemo, useRef, useState } from "react";
import { IconSearch } from "./icons.jsx";

// Cmd/Ctrl+K global search across cases and their findings.
export default function CommandPalette({ analyses, onOpen, views, setView }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const inputRef = useRef();

  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault(); setOpen((o) => !o);
      }
      if (e.key === "Escape") setOpen(false);
    };
    const onTrigger = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener("open-cmdk", onTrigger);
    return () => { window.removeEventListener("keydown", onKey); window.removeEventListener("open-cmdk", onTrigger); };
  }, []);

  useEffect(() => { if (open) { setQ(""); setTimeout(() => inputRef.current?.focus(), 30); } }, [open]);

  const results = useMemo(() => {
    const term = q.trim().toLowerCase();
    const out = [];
    for (const v of views) {
      if (!term || v.label.toLowerCase().includes(term))
        out.push({ type: "view", id: v.id, label: v.label, sub: "Go to page" });
    }
    for (const a of analyses) {
      if (a.status !== "completed") continue;
      const hay = `${a.filename} ${a.module} ${a.severity}`.toLowerCase();
      if (!term || hay.includes(term))
        out.push({ type: "case", id: a.id, label: a.filename, sub: `${a.module} · ${a.severity} · score ${a.score}`, severity: a.severity });
      for (const f of a.report?.findings || []) {
        if (term && `${f.title} ${f.description}`.toLowerCase().includes(term))
          out.push({ type: "case", id: a.id, label: f.title, sub: `finding in ${a.filename}`, severity: f.severity });
      }
    }
    return out.slice(0, 20);
  }, [q, analyses, views]);

  if (!open) return null;

  const pick = (r) => {
    setOpen(false);
    if (r.type === "view") setView(r.id);
    else onOpen(r.id);
  };

  return (
    <div className="cmd-overlay" onClick={() => setOpen(false)}>
      <div className="cmd" onClick={(e) => e.stopPropagation()}>
        <div className="cmd-input">
          <IconSearch size={18} />
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="Search cases, findings, pages…" />
          <kbd>esc</kbd>
        </div>
        <div className="cmd-results">
          {results.length === 0 && <div className="cmd-empty">No matches</div>}
          {results.map((r, i) => (
            <div key={i} className="cmd-row" onClick={() => pick(r)}>
              {r.severity ? <span className="dot" style={{ background: `var(--${r.severity})` }} /> : <span className="cmd-kind">{r.type === "view" ? "▸" : "◎"}</span>}
              <span className="cmd-label">{r.label}</span>
              <span className="cmd-sub">{r.sub}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
