import React from "react";
import { PieChart, Pie, Cell, Legend, ResponsiveContainer, Tooltip } from "recharts";

const COLORS = {
  info: "#2dd4bf", low: "#facc15", medium: "#fb923c",
  high: "#ef5b15", critical: "#dc2626",
};

export default function SeverityChart({ distribution, height = 230 }) {
  const data = Object.entries(distribution || {})
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));
  if (!data.length) return <div className="muted">No findings.</div>;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85}
          paddingAngle={3} stroke="var(--card)" strokeWidth={2}>
          {data.map((d) => (
            <Cell key={d.name} fill={COLORS[d.name]}
              style={{ filter: `drop-shadow(0 0 5px ${COLORS[d.name]}aa)` }} />
          ))}
        </Pie>
        <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--border-bright)", borderRadius: 8, fontSize: 12 }} />
        <Legend formatter={(v) => <span style={{ color: "var(--text-dim)", fontSize: 11, textTransform: "uppercase", letterSpacing: 1 }}>{v}</span>} />
      </PieChart>
    </ResponsiveContainer>
  );
}
