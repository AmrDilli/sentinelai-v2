import React, { useState } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend,
} from "recharts";

const SEV = [["critical", "#ef4444"], ["high", "#ef5b15"], ["medium", "#fb923c"], ["low", "#facc15"]];

// Bucket completed cases by day, counting findings per severity.
function buildSeries(analyses) {
  const byDay = {};
  for (const a of analyses) {
    if (a.status !== "completed" || !a.report) continue;
    const day = (a.report.generated_at || "").slice(0, 10) || "—";
    const bucket = byDay[day] || (byDay[day] = { day, critical: 0, high: 0, medium: 0, low: 0 });
    for (const [k, v] of Object.entries(a.report.severity_distribution || {})) {
      if (bucket[k] != null) bucket[k] += v;
    }
  }
  return Object.values(byDay).sort((a, b) => a.day.localeCompare(b.day));
}

// Limit the series to the selected look-back window (1W / 2W / 1M / All).
const RANGE_DAYS = { "1W": 7, "2W": 14, "1M": 30 };
function applyRange(series, range) {
  const days = RANGE_DAYS[range];
  if (!days) return series; // "All"
  const cutoff = new Date(Date.now() - days * 24 * 3600e3).toISOString().slice(0, 10);
  return series.filter((d) => d.day >= cutoff);
}

export default function TrendsPage({ analyses }) {
  const [range, setRange] = useState("All");
  const data = applyRange(buildSeries(analyses), range);

  return (
    <div className="view-enter">
      <div className="page-head"><h1>Threat Trends</h1>
        <span className="sub">Finding volume by severity over time</span></div>

      <div className="card">
        <div className="card-title">Alert Volume Trend
          <div className="seg">
            {["1W", "2W", "1M", "All"].map((r) => (
              <button key={r} className={range === r ? "on" : ""} onClick={() => setRange(r)}>{r}</button>
            ))}
          </div>
        </div>
        {data.length ? (
          <ResponsiveContainer width="100%" height={320}>
            <AreaChart data={data} margin={{ left: -10, right: 10, top: 10 }}>
              <defs>
                {SEV.map(([k, c]) => (
                  <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={c} stopOpacity={0.45} />
                    <stop offset="100%" stopColor={c} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="day" tick={{ fill: "var(--text-mute)", fontSize: 11 }} />
              <YAxis tick={{ fill: "var(--text-mute)", fontSize: 11 }} allowDecimals={false} />
              <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--border-bright)", borderRadius: 8, fontSize: 12 }} />
              <Legend />
              {SEV.map(([k, c]) => (
                <Area key={k} type="monotone" dataKey={k} stroke={c} fill={`url(#g-${k})`} strokeWidth={2} stackId="1" />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        ) : <div className="empty"><span className="big">📈</span>Analyze a few cases to populate trends.</div>}
      </div>
    </div>
  );
}
