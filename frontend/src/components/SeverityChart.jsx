import React from "react";
import { PieChart, Pie, Cell, Legend, ResponsiveContainer, Tooltip } from "recharts";

const COLORS = {
  info: "#64748b", low: "#38bdf8", medium: "#fbbf24",
  high: "#fb923c", critical: "#f43f5e",
};

export default function SeverityChart({ distribution }) {
  const data = Object.entries(distribution)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));
  if (!data.length) return <div className="muted">No findings.</div>;
  return (
    <ResponsiveContainer width="100%" height={230}>
      <PieChart>
        <Pie
          data={data} dataKey="value" nameKey="name"
          innerRadius={55} outerRadius={85} paddingAngle={3}
          stroke="#04070d" strokeWidth={2}
        >
          {data.map((d) => <Cell key={d.name} fill={COLORS[d.name]} />)}
        </Pie>
        <Tooltip
          contentStyle={{
            background: "#0d1421", border: "1px solid #2c4368",
            borderRadius: 8, fontFamily: "JetBrains Mono, monospace", fontSize: 12,
          }}
          itemStyle={{ color: "#d7e2f0" }}
        />
        <Legend
          formatter={(v) => <span style={{ color: "#6b7c96", fontSize: 11, textTransform: "uppercase", letterSpacing: 1 }}>{v}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
