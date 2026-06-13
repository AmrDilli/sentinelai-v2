import React from "react";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

// Bucket findings by weekday × hour-of-day from each case's generated_at, weighted
// by severity — a GitHub-style activity grid like the mockup's "Weekly Pattern".
const SEV_WEIGHT = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export default function ActivityHeatmap({ analyses }) {
  const grid = Array.from({ length: 7 }, () => new Array(24).fill(0));
  let any = false;
  for (const a of analyses) {
    if (a.status !== "completed" || !a.report) continue;
    const ts = a.report.generated_at;
    const d = ts ? new Date(ts) : null;
    if (!d || isNaN(d)) continue;
    const day = (d.getDay() + 6) % 7; // Mon=0
    const hour = d.getHours();
    let weight = 0;
    for (const [k, v] of Object.entries(a.report.severity_distribution || {})) {
      weight += (SEV_WEIGHT[k] || 0) * v;
    }
    grid[day][hour] += weight || 1;
    any = true;
  }
  const max = Math.max(1, ...grid.flat());

  const color = (v) => {
    if (v === 0) return "var(--panel-2)";
    const t = v / max;
    if (t > 0.75) return "var(--critical)";
    if (t > 0.5) return "var(--high)";
    if (t > 0.25) return "var(--medium)";
    return "var(--low)";
  };

  if (!any) return <div className="empty">Analyze cases to build the activity pattern.</div>;

  return (
    <div className="heatmap">
      <div className="hm-hours">
        <span /> <span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span>
      </div>
      {DAYS.map((day, di) => (
        <div key={day} className="hm-day">
          <span className="hm-daylabel">{day}</span>
          <div className="hm-cells">
            {grid[di].map((v, hi) => (
              <div key={hi} className="hm-cell" style={{ background: color(v) }}
                title={`${day} ${hi}:00 — activity ${v}`} />
            ))}
          </div>
        </div>
      ))}
      <div className="hm-legend">
        <span>Low</span>
        <i style={{ background: "var(--low)" }} /><i style={{ background: "var(--medium)" }} />
        <i style={{ background: "var(--high)" }} /><i style={{ background: "var(--critical)" }} />
        <span>High</span>
      </div>
    </div>
  );
}
