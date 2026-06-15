import React, { useRef, useState } from "react";
import { uploadFile } from "../api/client.js";
import { IconUpload } from "./icons.jsx";

// Mirrors the backend allow-list (orchestrator.ALLOWED_EXTS) for the file picker
// + a friendly client-side check; the server is the real enforcement boundary.
const ALLOWED = [
  ".pcap", ".cap", ".pcapng", ".evtx", ".xml", ".jsonl", ".json",
  ".exe", ".dll", ".sys", ".scr", ".com", ".bin", ".dat", ".msi", ".ps1",
  ".vbs", ".bat", ".js", ".jar", ".hta", ".lnk", ".doc", ".docx", ".xls",
  ".xlsx", ".rtf", ".pdf", ".zip", ".elf", ".o", ".so", ".apk",
];
const extOf = (name) => { const i = (name || "").lastIndexOf("."); return i < 0 ? "" : name.slice(i).toLowerCase(); };

export default function UploadPanel({ onUploaded, toast, compact }) {
  const inputRef = useRef();
  const [module, setModule] = useState("");
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);

  const handleFiles = async (files) => {
    if (!files?.length) return;
    const accepted = [...files].filter((f) => ALLOWED.includes(extOf(f.name)));
    const rejected = [...files].filter((f) => !ALLOWED.includes(extOf(f.name)));
    if (rejected.length) {
      toast?.(`Unsupported file type: ${rejected.map((f) => f.name).join(", ")}`, "critical");
    }
    if (!accepted.length) return;
    setBusy(true);
    try {
      for (const file of accepted) await uploadFile(file, module || undefined);
      toast?.(`${accepted.length} file(s) ingested — analyzing`, "info");
      onUploaded();
    } catch (e) {
      toast?.(e.message, "critical");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={compact ? "" : "card"}>
      {!compact && <div className="card-title">Ingest Artifact</div>}
      <div
        className={`dropzone ${drag ? "drag" : ""}`}
        onClick={() => inputRef.current.click()}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); handleFiles(e.dataTransfer.files); }}
      >
        <span className="ico"><IconUpload size={26} /></span>
        {busy ? "Uploading…" : "Drop a PCAP, event log, or suspicious file — or click to browse"}
        <input ref={inputRef} type="file" multiple accept={ALLOWED.join(",")}
          onChange={(e) => handleFiles(e.target.files)} />
      </div>
      <div style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "center" }}>
        <span className="muted" style={{ fontSize: 12 }}>Module</span>
        <select className="tb-select" value={module} onChange={(e) => setModule(e.target.value)} style={{ flex: 1 }}>
          <option value="">Auto-detect</option>
          <option value="network">Network (PCAP)</option>
          <option value="forensics">Forensics (event log)</option>
          <option value="malware">Malware (static)</option>
        </select>
      </div>
    </div>
  );
}
