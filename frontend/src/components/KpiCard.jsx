import React from "react";
import { useCountUp } from "../useCountUp.js";

export default function KpiCard({ label, value, suffix = "", decimals = 0, delta, deltaDir = "flat", color = "var(--brand)", Icon, index = 0, onClick }) {
  const animated = useCountUp(typeof value === "number" ? value : 0);
  const shown = typeof value === "number"
    ? animated.toFixed(decimals)
    : value;
  return (
    <div className={`kpi ${onClick ? "clickable" : ""}`} style={{ animationDelay: `${index * 0.06}s` }}
      onClick={onClick} role={onClick ? "button" : undefined} tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => (e.key === "Enter" || e.key === " ") && onClick() : undefined}>
      <div className="kpi-top">
        <span className="kpi-label">{label}</span>
        <span className="kpi-icon" style={{ background: `color-mix(in srgb, ${color} 16%, transparent)`, color }}>
          {Icon && <Icon size={20} />}
        </span>
      </div>
      <div className="kpi-val">{shown}{suffix}</div>
      {delta && <div className={`kpi-delta ${deltaDir}`}>{delta}</div>}
      {onClick && <span className="kpi-go" aria-hidden="true">›</span>}
    </div>
  );
}
