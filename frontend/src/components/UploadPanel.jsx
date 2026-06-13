import React, { useRef, useState } from "react";
import { uploadFile } from "../api/client.js";
import { IconUpload } from "./icons.jsx";

export default function UploadPanel({ onUploaded, toast, compact }) {
  const inputRef = useRef();
  const [module, setModule] = useState("");
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);

  const handleFiles = async (files) => {
    if (!files?.length) return;
    setBusy(true);
    try {
      for (const file of files) await uploadFile(file, module || undefined);
      toast?.(`${files.length} file(s) ingested — analyzing`, "info");
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
        <input ref={inputRef} type="file" multiple onChange={(e) => handleFiles(e.target.files)} />
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
