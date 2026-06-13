import React from "react";
import { LAND } from "./world-land.js";

// Equirectangular projection: lon/lat -> x/y inside the viewBox.
const W = 720, H = 360;
const project = (lon, lat) => [((lon + 180) / 360) * W, ((90 - lat) / 180) * H];

// Pre-build the SVG path for all landmasses once at module load.
const LAND_PATH = LAND.map(
  (ring) => "M" + ring.map(([lon, lat]) => project(lon, lat).map((n) => n.toFixed(1)).join(",")).join("L") + "Z"
).join(" ");

export default function GeoMap({ geo, reputation }) {
  const entries = Object.entries(geo || {}).filter(
    ([, g]) => typeof g?.lat === "number" && typeof g?.lon === "number"
  );
  if (!entries.length) {
    return <div className="muted">No geolocation data. Add an enrichment key (ip-api is keyless) and re-run.</div>;
  }

  const isBad = (ip) => (reputation?.[ip]?.abuse_confidence || 0) >= 50;

  // "Home" = the monitored network. Place it at the average of internal traffic,
  // or default to roughly central US if we only have external points.
  const home = project(-95, 39);

  // Group endpoints by country for the readable side list.
  const byCountry = {};
  for (const [ip, g] of entries) {
    const c = g.country || "Unknown";
    (byCountry[c] = byCountry[c] || { ips: [], bad: 0 }).ips.push(ip);
    if (isBad(ip)) byCountry[c].bad++;
  }
  const countries = Object.entries(byCountry).sort((a, b) => b[1].ips.length - a[1].ips.length);

  return (
    <div className="geo-layout">
      <svg viewBox={`0 0 ${W} ${H}`} className="geomap">
        {/* graticule */}
        {[...Array(13)].map((_, i) => (
          <line key={`v${i}`} x1={(i / 12) * W} y1="0" x2={(i / 12) * W} y2={H} className="grat" />
        ))}
        {[...Array(7)].map((_, i) => (
          <line key={`h${i}`} x1="0" y1={(i / 6) * H} x2={W} y2={(i / 6) * H} className="grat" />
        ))}

        {/* real world landmasses */}
        <path d={LAND_PATH} className="geo-land" />

        {/* connection lines (curved arcs from home to each endpoint) */}
        {entries.map(([ip, g]) => {
          const [x, y] = project(g.lon, g.lat);
          const mx = (home[0] + x) / 2, my = (home[1] + y) / 2 - Math.abs(x - home[0]) * 0.18;
          return (
            <path key={`l${ip}`} d={`M${home[0]},${home[1]} Q${mx},${my} ${x},${y}`}
              fill="none" className={isBad(ip) ? "geo-link bad" : "geo-link"} />
          );
        })}

        {/* destination nodes */}
        {entries.map(([ip, g]) => {
          const [x, y] = project(g.lon, g.lat);
          const bad = isBad(ip);
          const conf = reputation?.[ip]?.abuse_confidence || 0;
          return (
            <g key={ip}>
              {bad && <circle cx={x} cy={y} r="9" className="geo-pulse" />}
              <circle cx={x} cy={y} r={bad ? 5.5 : 4} className={bad ? "geo-node bad" : "geo-node"}>
                <title>{`${ip}\n${g.city ? g.city + ", " : ""}${g.country || ""}\n${g.org || ""}${conf ? `\nAbuse: ${conf}%` : ""}`}</title>
              </circle>
            </g>
          );
        })}

        {/* home node */}
        <circle cx={home[0]} cy={home[1]} r="7" className="geo-pulse home" />
        <circle cx={home[0]} cy={home[1]} r="5" className="geo-home" />
        <text x={home[0]} y={home[1] + 18} className="geo-label home" textAnchor="middle">
          MONITORED NET
        </text>
      </svg>

      {/* readable country breakdown */}
      <div className="geo-list">
        <div className="geo-list-head">{entries.length} endpoints · {countries.length} countries</div>
        {countries.map(([country, info]) => (
          <div key={country} className={`geo-row ${info.bad ? "bad" : ""}`}>
            <span className="geo-dot" />
            <span className="geo-country">{country}</span>
            <span className="geo-num">{info.ips.length}</span>
            {info.bad > 0 && <span className="geo-badge">{info.bad} flagged</span>}
          </div>
        ))}
      </div>
    </div>
  );
}
