import React, { useState, useEffect } from "react";
import { IconChip, IconCloud, IconNetwork, IconShield, IconCheck } from "../components/icons.jsx";
import { refreshThreatIntel, getSettings, updateSettings } from "../api/client.js";

function Integration({ Icon, color, name, desc, connected, detail }) {
  return (
    <div className="intg">
      <div className="intg-top">
        <span className="intg-ico" style={{ background: `color-mix(in srgb, ${color} 16%, transparent)`, color }}>
          <Icon size={22} />
        </span>
        <div className={`switch ${connected ? "on" : ""}`} style={{ pointerEvents: "none" }} />
      </div>
      <h3>{name}</h3>
      <div className="desc">{desc}</div>
      <div className="intg-foot">
        <span className={`conn-dot ${connected ? "on" : "off"}`}><i />{connected ? "Connected" : "Not configured"}</span>
        <span className="muted">{detail}</span>
      </div>
    </div>
  );
}

const BLANK = { ai_provider: "", deepseek_api_key: "", anthropic_api_key: "", abuseipdb_api_key: "", virustotal_api_key: "" };

export default function SettingsPage({ health, toast }) {
  const [cfg, setCfg] = useState(null);
  const [form, setForm] = useState(BLANK);
  const [saving, setSaving] = useState(false);
  const [intel, setIntel] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => { getSettings().then(setCfg).catch(() => {}); }, []);

  const selectedProvider = form.ai_provider || cfg?.ai_provider || health?.ai_provider || "mock";
  const activeProvider = cfg?.active_provider || selectedProvider;
  const aiConnected = activeProvider !== "mock";
  const keySet = (k) => cfg?.keys?.[k] ?? !!health?.enrichment?.[k];
  const ti = intel || health?.threat_intel || {};

  const set = (field) => (e) => setForm((f) => ({ ...f, [field]: e.target.value }));

  const save = async () => {
    const updates = {};
    if (form.ai_provider) updates.ai_provider = form.ai_provider;
    for (const f of ["deepseek_api_key", "anthropic_api_key", "abuseipdb_api_key", "virustotal_api_key"]) {
      if (form[f].trim()) updates[f] = form[f].trim();
    }
    if (!Object.keys(updates).length) { toast?.("Nothing to save", "info"); return; }
    setSaving(true);
    try {
      setCfg(await updateSettings(updates));
      setForm(BLANK);
      toast?.("Settings saved — applied live, no restart needed", "success");
    } catch (e) {
      toast?.(e.message, "critical");
    } finally {
      setSaving(false);
    }
  };

  const doRefresh = async () => {
    setRefreshing(true);
    try {
      const res = await refreshThreatIntel();
      setIntel(res);
      toast?.(res.ok === false
        ? `Threat-intel refresh failed: ${res.error || "offline"}`
        : `Threat intel updated — ${res.ja3} JA3, ${res.ips} IPs, ${res.domains} domains`,
        res.ok === false ? "critical" : "success");
    } catch (e) {
      toast?.(e.message, "critical");
    } finally {
      setRefreshing(false);
    }
  };

  const KeyField = ({ label, field, set: setKey }) => (
    <label className="key-field">
      <span>{label} {keySet(setKey) && <em className="key-ok">configured</em>}</span>
      <input type="password" autoComplete="off" value={form[field]} onChange={set(field)}
        placeholder={keySet(setKey) ? "•••••••• (leave blank to keep)" : "paste key to enable"} />
    </label>
  );

  return (
    <div className="view-enter">
      <div className="page-head"><h1>Settings &amp; Integrations</h1>
        <span className="sub">AI engine and threat-intel sources</span></div>

      <div className="kpi-grid" style={{ marginBottom: 24 }}>
        <div className="kpi"><div className="kpi-top"><span className="kpi-label">AI Engine</span>
          <span className="kpi-icon" style={{ background: "color-mix(in srgb, var(--brand) 16%, transparent)", color: "var(--brand)" }}><IconChip size={20} /></span></div>
          <div className="kpi-val" style={{ fontSize: 26 }}>{activeProvider}</div>
          <div className={`kpi-delta ${aiConnected ? "down" : "flat"}`}>{aiConnected ? "live reasoning" : "offline / mock"}</div></div>
        <div className="kpi"><div className="kpi-top"><span className="kpi-label">Self-Verify</span>
          <span className="kpi-icon" style={{ background: "color-mix(in srgb, var(--green) 16%, transparent)", color: "var(--green)" }}><IconCheck size={20} /></span></div>
          <div className="kpi-val" style={{ fontSize: 26 }}>{health?.self_verify ? "On" : "Off"}</div>
          <div className="kpi-delta flat">AI_SELF_VERIFY</div></div>
        <div className="kpi"><div className="kpi-top"><span className="kpi-label">Response Cache</span>
          <span className="kpi-icon" style={{ background: "color-mix(in srgb, var(--accent) 16%, transparent)", color: "var(--accent)" }}><IconShield size={20} /></span></div>
          <div className="kpi-val" style={{ fontSize: 26 }}>{health?.cache ? "On" : "Off"}</div>
          <div className="kpi-delta flat">AI_CACHE</div></div>
        <div className="kpi"><div className="kpi-top"><span className="kpi-label">Backend</span>
          <span className="kpi-icon" style={{ background: "color-mix(in srgb, var(--green) 16%, transparent)", color: "var(--green)" }}><IconNetwork size={20} /></span></div>
          <div className="kpi-val" style={{ fontSize: 26 }}>{health ? "Online" : "Offline"}</div>
          <div className="kpi-delta down">FastAPI</div></div>
      </div>

      {/* Editable API keys + provider — saved server-side, applied live */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-title">API Keys &amp; AI Provider
          <span className="h2-actions">
            <button className="btn sm primary" onClick={save} disabled={saving}>{saving ? "Saving…" : "Save"}</button>
          </span>
        </div>
        <p className="dim" style={{ fontSize: 12.5, marginBottom: 14 }}>
          Keys are stored on the server and applied immediately — no restart, no editing files.
          They are never sent back to the browser; blank fields keep the existing value.
        </p>
        <div className="key-grid">
          <label className="key-field">
            <span>AI provider</span>
            <select className="tb-select" value={selectedProvider}
              onChange={(e) => setForm((f) => ({ ...f, ai_provider: e.target.value }))}>
              <option value="mock">mock (offline, no key)</option>
              <option value="deepseek">deepseek</option>
              <option value="claude">claude</option>
            </select>
          </label>
          <KeyField label="DeepSeek API key" field="deepseek_api_key" set="deepseek" />
          <KeyField label="Anthropic (Claude) API key" field="anthropic_api_key" set="anthropic" />
          <KeyField label="AbuseIPDB API key" field="abuseipdb_api_key" set="abuseipdb" />
          <KeyField label="VirusTotal API key" field="virustotal_api_key" set="virustotal" />
        </div>
      </div>

      <div className="page-head" style={{ marginBottom: 14 }}><h1 style={{ fontSize: 20 }}>Connectors</h1>
        <span className="sub">Live status of each enrichment source</span></div>
      <div className="intg-grid">
        <Integration Icon={IconChip} color="#6366f1" name="DeepSeek / Claude"
          desc="AI reasoning engine. Choose the provider and key above."
          connected={aiConnected} detail={activeProvider} />
        <Integration Icon={IconNetwork} color="#f97316" name="AbuseIPDB"
          desc="IP reputation enrichment for the network module."
          connected={keySet("abuseipdb")} detail={keySet("abuseipdb") ? "key set" : "—"} />
        <Integration Icon={IconShield} color="#22c55e" name="VirusTotal"
          desc="File-hash reputation for the malware module."
          connected={keySet("virustotal")} detail={keySet("virustotal") ? "key set" : "—"} />
        <Integration Icon={IconCloud} color="#38bdf8" name="IP Geolocation"
          desc="Keyless geolocation (ip-api.com) — powers the world map."
          connected detail="keyless" />
      </div>

      <div className="card" style={{ marginTop: 24 }}>
        <div className="card-title">
          Threat-Intelligence Feed
          <span className="h2-actions">
            <button className="btn sm primary" onClick={doRefresh} disabled={refreshing}>
              {refreshing ? "Refreshing…" : "Refresh from abuse.ch"}
            </button>
          </span>
        </div>
        <p className="dim" style={{ fontSize: 13, lineHeight: 1.6, marginBottom: 12 }}>
          JA3 fingerprints and known-bad IPs/domains power the network module's
          highest-confidence detections. Ships with a bundled offline snapshot
          (source: <b>{ti.source || "bundled"}</b>, v{ti.version || "—"}) and can pull
          live indicators from abuse.ch on demand.
          {ti.last_updated ? ` Last live refresh: ${ti.last_updated}.` : ""}
        </p>
        <div className="stat-row">
          <div className="stat-box"><div className="stat-val">{ti.ja3 ?? "—"}</div><div className="stat-lbl">JA3 fingerprints</div></div>
          <div className="stat-box"><div className="stat-val">{ti.ips ?? "—"}</div><div className="stat-lbl">Known-bad IPs</div></div>
          <div className="stat-box"><div className="stat-val">{ti.domains ?? "—"}</div><div className="stat-lbl">Known-bad domains</div></div>
        </div>
      </div>
    </div>
  );
}
