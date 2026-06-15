import React from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";

const tooltipStyle = {
  background: "#0d1421", border: "1px solid #2c4368",
  borderRadius: 8, fontFamily: "JetBrains Mono, monospace", fontSize: 12,
};

// Module-specific quick-stat charts driven by summary.stats.
export default function StatsCharts({ summary }) {
  const { module, stats } = summary;

  if (module === "network" && stats.protocol_breakdown) {
    const data = Object.entries(stats.protocol_breakdown)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
    return (
      <>
        <ChartBlock title="Protocol breakdown" data={data} color="#22d3ee" unit="packets" />
        <div className="stat-row">
          <Stat label="Packets" value={stats.packets?.toLocaleString()} />
          <Stat label="Flows" value={stats.flows?.toLocaleString()} />
          <Stat label="Ext. IPs" value={stats.unique_external_ips} />
          <Stat label="Duration" value={`${stats.duration_seconds}s`} />
        </div>
      </>
    );
  }

  if (module === "forensics" && stats.event_id_frequency) {
    const data = Object.entries(stats.event_id_frequency)
      .slice(0, 10)
      .map(([id, v]) => ({ name: id, value: v.count, meaning: v.meaning }));
    return (
      <>
        <ChartBlock title="Top event IDs" data={data} color="#fbbf24" unit="events" labelKey="meaning" />
        <div className="stat-row">
          <Stat label="Events" value={stats.events?.toLocaleString()} />
          <Stat label="Unique IDs" value={stats.unique_event_ids} />
        </div>
      </>
    );
  }

  if (module === "malware") {
    const sections = (summary.observations || [])
      .filter((o) => o.data?.name && typeof o.data?.entropy === "number");
    const data = sections.map((o) => ({ name: o.data.name, value: o.data.entropy }));
    const cls = stats.classification;
    const vt = summary.enrichment?.virustotal;
    return (
      <>
        {cls && (
          <div className={`malware-verdict ${cls.confidence}`}>
            <span className="mv-label">Classification</span>
            <span className="mv-type">{cls.type}</span>
            <span className="mv-conf">{cls.confidence} confidence</span>
            {vt && vt.malicious > 0 && <span className="mv-vt">VirusTotal: {vt.malicious} engines</span>}
          </div>
        )}
        {data.length > 0 && (
          <ChartBlock title="Section entropy (0–8)" data={data} color="#fb923c" unit="" max={8} />
        )}
        <div className="stat-row">
          <Stat label="Size" value={`${(stats.size_bytes / 1024).toFixed(1)} KB`} />
          <Stat label="Entropy" value={stats.overall_entropy} />
          <Stat label="Signed" value={stats.is_signed ? "Yes" : "No"} />
          <Stat label="APIs" value={stats.suspicious_api_count} />
        </div>
      </>
    );
  }
  return <div className="muted">No chartable stats.</div>;
}

function ChartBlock({ title, data, color, unit, labelKey, max }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div className="chart-title">{title}</div>
      <ResponsiveContainer width="100%" height={Math.max(120, data.length * 26)}>
        <BarChart data={data} layout="vertical" margin={{ left: 4, right: 18, top: 4, bottom: 4 }}>
          <XAxis type="number" hide domain={max ? [0, max] : undefined} />
          <YAxis type="category" dataKey="name" width={64}
            tick={{ fill: "#6b7c96", fontSize: 11, fontFamily: "JetBrains Mono" }} />
          <Tooltip
            contentStyle={tooltipStyle} itemStyle={{ color: "#d7e2f0" }} cursor={{ fill: "rgba(34,211,238,0.05)" }}
            formatter={(v, _n, p) => [`${v}${unit ? " " + unit : ""}`, p.payload[labelKey] || ""]} />
          <Bar dataKey="value" radius={[0, 4, 4, 0]}>
            {data.map((_, i) => <Cell key={i} fill={color} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="stat-box">
      <div className="stat-val">{value ?? "—"}</div>
      <div className="stat-lbl">{label}</div>
    </div>
  );
}
