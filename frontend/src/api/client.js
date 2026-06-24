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
// Load the bundled demo cases (zero-setup exploration of a populated console).
export async function loadSampleCase() {
  return asJson(await fetch(`${BASE}/analyze/sample`, { method: "POST", headers: authHeaders() }));
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
export async function setTriage(analysisId, findingIndex, status) {
  return asJson(await fetch(`${BASE}/analyses/${analysisId}/triage`, {
    method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ finding_index: findingIndex, status }),
  }));
}
export async function explainFinding(analysisId, findingIndex) {
  return asJson(await fetch(`${BASE}/analyses/${analysisId}/explain`, {
    method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ finding_index: findingIndex }),
  }));
}
export async function getSettings() {
  return asJson(await fetch(`${BASE}/settings`, { headers: authHeaders() }));
}
export async function updateSettings(updates) {
  return asJson(await fetch(`${BASE}/settings/keys`, {
    method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(updates),
  }));
}
// ---- live capture ----
export async function listScenarios() {
  return (await asJson(await fetch(`${BASE}/live/scenarios`, { headers: authHeaders() }))).scenarios;
}
export async function listInterfaces() {
  return asJson(await fetch(`${BASE}/live/interfaces`, { headers: authHeaders() })); // { interfaces, default }
}
export async function startLive(opts) {
  const body = typeof opts === "string" ? { scenario: opts } : (opts || {});
  return asJson(await fetch(`${BASE}/live/start`, {
    method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  }));
}
export async function stopLive(sessionId) {
  return asJson(await fetch(`${BASE}/live/stop/${sessionId}`, { method: "POST", headers: authHeaders() }));
}
export async function snapshotLive(sessionId) {
  return asJson(await fetch(`${BASE}/live/${sessionId}/snapshot`, { method: "POST", headers: authHeaders() }));
}
// Build the authenticated WebSocket URL for a live session.
export function liveSocketUrl(sessionId) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}${BASE}/ws/live/${sessionId}?token=${encodeURIComponent(getToken())}`;
}

// ---- IOC watchlist ----
export async function listWatchlist() {
  return (await asJson(await fetch(`${BASE}/watchlist`, { headers: authHeaders() }))).indicators;
}
export async function addWatchlist(indicator) {
  return asJson(await fetch(`${BASE}/watchlist`, {
    method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(indicator),
  }));
}
export async function removeWatchlist(id) {
  return asJson(await fetch(`${BASE}/watchlist/${id}`, { method: "DELETE", headers: authHeaders() }));
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
