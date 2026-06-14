import React, { useEffect, useRef } from "react";

// Subtle drifting particle field behind the app (cyan/blue, low opacity).
// Sits below content (z-index -1) and is purely decorative.
export default function Particles({ count = 46 }) {
  const ref = useRef(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
    const ctx = canvas.getContext("2d");
    const COLORS = ["56,189,248", "34,211,238", "59,130,246"];
    let w, h, dots = [], raf;

    const resize = () => { w = canvas.width = window.innerWidth; h = canvas.height = window.innerHeight; };
    const init = () => {
      dots = Array.from({ length: count }, () => ({
        x: Math.random() * w, y: Math.random() * h,
        r: Math.random() * 1.4 + 0.5,
        vx: (Math.random() - 0.5) * 0.16,
        vy: (Math.random() - 0.5) * 0.16,
        a: Math.random() * 0.4 + 0.12,
        c: COLORS[(Math.random() * COLORS.length) | 0],
      }));
    };
    const tick = () => {
      ctx.clearRect(0, 0, w, h);
      for (const d of dots) {
        d.x += d.vx; d.y += d.vy;
        if (d.x < -2) d.x = w + 2; else if (d.x > w + 2) d.x = -2;
        if (d.y < -2) d.y = h + 2; else if (d.y > h + 2) d.y = -2;
        ctx.beginPath();
        ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
        ctx.shadowBlur = 6; ctx.shadowColor = `rgba(${d.c},${d.a})`;
        ctx.fillStyle = `rgba(${d.c},${d.a})`;
        ctx.fill();
      }
      raf = requestAnimationFrame(tick);
    };

    resize(); init(); tick();
    const onResize = () => { resize(); init(); };
    window.addEventListener("resize", onResize);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", onResize); };
  }, [count]);

  return <canvas ref={ref} className="particles" aria-hidden="true" />;
}
