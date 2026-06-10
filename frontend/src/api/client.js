const BASE = "/api";

export async function uploadFile(file, module) {
  const form = new FormData();
  form.append("file", file);
  if (module) form.append("module", module);
  const res = await fetch(`${BASE}/analyze`, { method: "POST", body: form });
  if (!res.ok) throw new Error((await res.json()).detail || "Upload failed");
  return res.json();
}

export async function listAnalyses() {
  const res = await fetch(`${BASE}/analyses`);
  return (await res.json()).analyses;
}

export async function getAnalysis(id) {
  const res = await fetch(`${BASE}/analyses/${id}`);
  if (!res.ok) throw new Error("Not found");
  return res.json();
}

export async function correlate(ids) {
  const res = await fetch(`${BASE}/correlate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(ids),
  });
  if (!res.ok) throw new Error((await res.json()).detail || "Correlation failed");
  return res.json();
}

export async function approveAction(analysisId, actionIndex) {
  const res = await fetch(
    `${BASE}/soar/${analysisId}/approve?action_index=${actionIndex}`,
    { method: "POST" }
  );
  if (!res.ok) throw new Error((await res.json()).detail || "Approval failed");
  return res.json();
}
