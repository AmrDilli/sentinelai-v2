import React from "react";
import { IconChip, IconCloud, IconNetwork, IconShield, IconCheck } from "../components/icons.jsx";

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

export default function SettingsPage({ health }) {
  const provider = health?.ai_provider || "mock";
  const aiConnected = provider !== "mock";

  return (
    <div className="view-enter">
      <div className="page-head"><h1>Settings &amp; Integrations</h1>
        <span className="sub">AI engine and threat-intel sources</span></div>

      <div className="kpi-grid" style={{ marginBottom: 24 }}>
        <div className="kpi"><div className="kpi-top"><span className="kpi-label">AI Engine</span>
          <span className="kpi-icon" style={{ background: "color-mix(in srgb, var(--brand) 16%, transparent)", color: "var(--brand)" }}><IconChip size={20} /></span></div>
          <div className="kpi-val" style={{ fontSize: 26 }}>{provider}</div>
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

      <div className="page-head" style={{ marginBottom: 14 }}><h1 style={{ fontSize: 20 }}>Threat-Intel Integrations</h1>
        <span className="sub">Connect enrichment sources via .env keys</span></div>
      <div className="intg-grid">
        <Integration Icon={IconChip} color="#6366f1" name="DeepSeek / Claude"
          desc="AI reasoning engine. Switch via AI_PROVIDER in .env."
          connected={aiConnected} detail={provider} />
        <Integration Icon={IconNetwork} color="#f97316" name="AbuseIPDB"
          desc="IP reputation enrichment for the network module."
          connected={!!health?.enrichment?.abuseipdb} detail={health?.enrichment?.abuseipdb ? "key set" : "—"} />
        <Integration Icon={IconShield} color="#22c55e" name="VirusTotal"
          desc="File-hash reputation for the malware module."
          connected={!!health?.enrichment?.virustotal} detail={health?.enrichment?.virustotal ? "key set" : "—"} />
        <Integration Icon={IconCloud} color="#38bdf8" name="IP Geolocation"
          desc="Keyless geolocation (ip-api.com) — powers the world map."
          connected detail="keyless" />
      </div>

      <div className="card" style={{ marginTop: 24 }}>
        <div className="card-title">How to configure</div>
        <p className="dim" style={{ lineHeight: 1.7, fontSize: 13 }}>
          Edit the <code style={{ color: "var(--brand)" }}>.env</code> file in the project root and restart the backend.
          Set <code style={{ color: "var(--accent)" }}>AI_PROVIDER=deepseek</code> (or <code style={{ color: "var(--accent)" }}>claude</code>) with the matching API key to enable live AI analysis.
          Add <code style={{ color: "var(--accent)" }}>ABUSEIPDB_API_KEY</code> and <code style={{ color: "var(--accent)" }}>VIRUSTOTAL_API_KEY</code> (free tiers) to light up the enrichment connectors above.
        </p>
      </div>
    </div>
  );
}
