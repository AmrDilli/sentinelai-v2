import React, { useRef, useState } from "react";
import { uploadFile } from "../api/client.js";

export default function UploadPanel({ onUploaded }) {
  const inputRef = useRef();
  const [module, setModule] = useState("");
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);
  const [error, setError] = useState("");

  const handleFiles = async (files) => {
    if (!files?.length) return;
    setBusy(true);
    setError("");
    try {
      for (const file of files) await uploadFile(file, module || undefined);
      onUploaded();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <h2>Ingest Artifact</h2>
      <div
        className={`dropzone ${drag ? "drag" : ""}`}
        onClick={() => inputRef.current.click()}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); handleFiles(e.dataTransfer.files); }}
      >
        <span className="dz-icon">⬡</span>
        {busy ? "TRANSMITTING…" : "DROP FILE / CLICK TO BROWSE"}
        <input ref={inputRef} type="file" multiple onChange={(e) => handleFiles(e.target.files)} />
      </div>
      <div style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "center" }}>
        <span className="muted" style={{ fontSize: 11, letterSpacing: 1 }}>MODULE</span>
        <select value={module} onChange={(e) => setModule(e.target.value)} style={{ flex: 1 }}>
          <option value="">Auto-detect</option>
          <option value="network">Network (PCAP)</option>
          <option value="forensics">Forensics (event log)</option>
          <option value="malware">Malware (static)</option>
        </select>
      </div>
      {error && <div className="error-box" style={{ marginTop: 8 }}>{error}</div>}
    </div>
  );
}
