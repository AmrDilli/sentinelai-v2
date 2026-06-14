import React, { useEffect, useState } from "react";

const COLORS = {
  info: "#2dd4bf", low: "#facc15", medium: "#fb923c",
  high: "#ef5b15", critical: "#ef4444",
};

export default function ScoreGauge({ score, severity }) {
  const [animated, setAnimated] = useState(0);
  const color = COLORS[severity] || COLORS.info;
  const R = 62;
  const CIRC = 2 * Math.PI * R;

  useEffect(() => {
    setAnimated(0);
    const start = performance.now();
    const dur = 900;
    let raf;
    const tick = (now) => {
      const t = Math.min(1, (now - start) / dur);
      const ease = 1 - Math.pow(1 - t, 3);
      setAnimated(Math.round(score * ease));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [score]);

  return (
    <div className="gauge-wrap">
      <svg width="150" height="150" viewBox="0 0 150 150">
        <circle cx="75" cy="75" r={R} fill="none" stroke="#1b2940" strokeWidth="9" />
        <circle
          cx="75" cy="75" r={R} fill="none"
          stroke={color} strokeWidth="9" strokeLinecap="round"
          strokeDasharray={CIRC}
          strokeDashoffset={CIRC * (1 - animated / 100)}
          style={{
            filter: `drop-shadow(0 0 8px ${color})`,
            transition: "stroke-dashoffset 60ms linear",
          }}
        />
      </svg>
      <div className="gauge-num">
        <span className={`val glow-${severity}`}>{animated}</span>
        <span className="lbl">Risk Score</span>
      </div>
    </div>
  );
}
