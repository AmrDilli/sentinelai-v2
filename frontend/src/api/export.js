// Report export helpers.
import { fetchReportPDF } from "./client.js";

export function exportJSON(report) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  download(blob, `sentinelai_${report.module}_${report.source_file}.json`);
}

// Primary PDF path: download the server-rendered, branded ReportLab PDF.
// Falls back to the in-browser print view if the server can't produce one
// (e.g. reportlab not installed → 501), so the button always does something.
export async function exportServerPDF(analysisId, report, toast) {
  try {
    const blob = await fetchReportPDF(analysisId);
    download(blob, `sentinelai_${report.module}_${report.source_file}.pdf`);
  } catch (e) {
    toast?.("Server PDF unavailable — opening printable view", "info");
    exportPDF(report);
  }
}

// "PDF" via the browser print dialog (Save as PDF) over a clean printable view.
export function exportPDF(report) {
  const w = window.open("", "_blank");
  if (!w) return;
  const sev = report.severity;
  const findings = report.findings.map((f) => `
    <div class="f f-${f.severity}">
      <h3>${esc(f.title)} <span class="b">${f.severity.toUpperCase()}</span>
        <small>conf ${(f.confidence * 100).toFixed(0)}%</small></h3>
      <p>${esc(f.description)}</p>
      ${f.mitre_techniques?.length ? `<p class="m">MITRE: ${f.mitre_techniques.join(", ")}</p>` : ""}
      ${f.remediation?.length ? `<ul>${f.remediation.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
    </div>`).join("");
  const playbook = report.playbook.map((s) => `
    <div class="p"><b>${s.step}. ${esc(s.title)}</b> <i>(${s.phase})</i>
      <p>${esc(s.instructions)}</p></div>`).join("");

  w.document.write(`<!doctype html><html><head><title>SentinelAI Report — ${esc(report.source_file)}</title>
  <style>
    body{font-family:-apple-system,Segoe UI,sans-serif;color:#111;max-width:800px;margin:30px auto;padding:0 20px;}
    h1{border-bottom:3px solid #0891b2;padding-bottom:8px}
    .score{font-size:48px;font-weight:700}
    .sev-critical{color:#dc2626}.sev-high{color:#ea580c}.sev-medium{color:#ca8a04}.sev-low{color:#0284c7}.sev-info{color:#64748b}
    .f{border-left:4px solid #ccc;padding:6px 14px;margin:10px 0;background:#f8fafc}
    .f-critical{border-color:#dc2626}.f-high{border-color:#ea580c}.f-medium{border-color:#ca8a04}.f-low{border-color:#0284c7}
    .b{font-size:11px;background:#111;color:#fff;padding:2px 6px;border-radius:4px}
    .m{font-family:monospace;font-size:12px;color:#0891b2}
    .p{margin:8px 0} small{color:#888;font-weight:400}
    @media print{.no-print{display:none}}
  </style></head><body>
    <h1>SentinelAI v2 — Analysis Report</h1>
    <p><b>Artifact:</b> ${esc(report.source_file)} &nbsp; <b>Module:</b> ${report.module}
       &nbsp; <b>Engine:</b> ${report.ai_provider} &nbsp; <b>Generated:</b> ${esc(report.generated_at || "")}</p>
    <p class="score sev-${sev}">${report.score}/100 <span style="font-size:18px">${sev.toUpperCase()}</span></p>
    <h2>Summary</h2><p>${esc(report.narrative)}</p>
    <h2>Findings (${report.findings.length})</h2>${findings}
    <h2>Investigation Playbook</h2>${playbook}
    <button class="no-print" onclick="window.print()" style="margin-top:20px;padding:10px 20px">Save as PDF</button>
  </body></html>`);
  w.document.close();
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}
