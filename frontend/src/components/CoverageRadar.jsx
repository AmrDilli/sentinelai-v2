import React from "react";
import {
  Radar, RadarChart, PolarGrid, PolarAngleAxis, ResponsiveContainer, Tooltip,
} from "recharts";

// Tactic coverage across all analyses, rendered as a radar like the mockup.
const TACTICS = [
  ["TA0001", "Initial Access"], ["TA0002", "Execution"], ["TA0003", "Persistence"],
  ["TA0004", "Priv Esc"], ["TA0005", "Defense Evasion"], ["TA0006", "Cred Access"],
  ["TA0007", "Discovery"], ["TA0008", "Lateral Move"], ["TA0011", "C2"],
  ["TA0010", "Exfiltration"], ["TA0040", "Impact"],
];

export default function CoverageRadar({ analyses }) {
  const counts = Object.fromEntries(TACTICS.map(([id]) => [id, 0]));
  for (const a of analyses) {
    for (const t of a.report?.mitre || []) {
      if (counts[t.tactic_id] != null) counts[t.tactic_id] += t.techniques.length;
    }
  }
  const max = Math.max(1, ...Object.values(counts));
  const data = TACTICS.map(([id, name]) => ({ tactic: name, value: counts[id], full: max }));

  return (
    <ResponsiveContainer width="100%" height={250}>
      <RadarChart data={data} outerRadius="72%">
        <PolarGrid stroke="var(--border-bright)" />
        <PolarAngleAxis dataKey="tactic" tick={{ fill: "var(--text-mute)", fontSize: 10 }} />
        <Radar dataKey="value" stroke="var(--brand)" fill="var(--brand)" fillOpacity={0.35} />
        <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--border-bright)", borderRadius: 8, fontSize: 12 }} />
      </RadarChart>
    </ResponsiveContainer>
  );
}
