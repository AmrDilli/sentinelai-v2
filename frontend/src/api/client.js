const BASE = "/api";

// ---- token storage ----
let TOKEN = localStorage.getItem("sai-token") || "";
export function setToken(t) {
  TOKEN = t || "";
  if (t) localStorage.setItem("sai-token", t);
  else localStorage.removeItem("sai-token");
}
export function getToken() { return TOKEN; }

function authHeaders(extra = {}) {
  return TOKEN ? { ...extra, Authorization: `Bearer ${TOKEN}` } : extra;
}

async function asJson(res) {
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* noop */ }
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// ---- auth ----
export async function register(username, password) {
  return asJson(await fetch(`${BASE}/auth/register`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  }));
}
export async function login(username, password) {
  return asJson(await fetch(`${BASE}/auth/login`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  }));
}
export async function logout() {
  try { await fetch(`${BASE}/auth/logout`, { method: "POST", headers: authHeaders() }); }
  finally { setToken(""); }
}
export async function me() {
  return asJson(await fetch(`${BASE}/auth/me`, { headers: authHeaders() }));
}

// ---- analyses ----
export async function uploadFile(file, module) {
  const form = new FormData();
  form.append("file", file);
  if (module) form.append("module", module);
  return asJson(await fetch(`${BASE}/analyze`, { method: "POST", headers: authHeaders(), body: form }));
}
export async function listAnalyses() {
  return (await asJson(await fetch(`${BASE}/analyses`, { headers: authHeaders() }))).analyses;
}
export async function getAnalysis(id) {
  return asJson(await fetch(`${BASE}/analyses/${id}`, { headers: authHeaders() }));
}
export async function correlate(ids) {
  return asJson(await fetch(`${BASE}/correlate`, {
    method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(ids),
  }));
}
export async function approveAction(analysisId, actionIndex) {
  return asJson(await fetch(`${BASE}/soar/${analysisId}/approve?action_index=${actionIndex}`,
    { method: "POST", headers: authHeaders() }));
}
export async function deleteAnalysis(id) {
  return asJson(await fetch(`${BASE}/analyses/${id}`, { method: "DELETE", headers: authHeaders() }));
}
export async function explainFinding(analysisId, findingIndex) {
  return asJson(await fetch(`${BASE}/analyses/${analysisId}/explain`, {
    method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ finding_index: findingIndex }),
  }));
}
export async function refreshThreatIntel() {
  return asJson(await fetch(`${BASE}/threatintel/refresh`, { method: "POST", headers: authHeaders() }));
}
// Fetch the server-rendered PDF for an analysis as a Blob. Auth lives in a
// header, so a plain <a download> can't be used — stream it then save.
export async function fetchReportPDF(id) {
  const res = await fetch(`${BASE}/analyses/${id}/report.pdf`, { headers: authHeaders() });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* not json */ }
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.blob();
}
