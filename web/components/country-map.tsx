"use client";

import { useRef, useState } from "react";
import { countryName } from "@/lib/countries";
import { fmtInt } from "@/lib/format";
import world from "@/lib/world-110m.json";

type Feature = {
  type: string;
  properties: { iso: string };
  geometry: { type: string; coordinates: number[][][] | number[][][][] };
};

const collection = world as { features: Feature[] };

function project(lon: number, lat: number, w: number, h: number): [number, number] {
  const pad = 6;
  const x = pad + ((lon + 180) / 360) * (w - 2 * pad);
  const y = pad + ((90 - lat) / 180) * (h - 2 * pad);
  return [x, y];
}

// A ring that crosses the antimeridian (Russia's Chukotka, Fiji) jumps from
// +180 to -180 and would draw a streak across the map. Shift the minority
// side by 360° so the ring stays whole; the part past the edge is clipped.
function unwrap(ring: number[][]): number[][] {
  let crosses = false;
  for (let i = 1; i < ring.length; i++) {
    if (Math.abs(ring[i][0] - ring[i - 1][0]) > 180) {
      crosses = true;
      break;
    }
  }
  if (!crosses) return ring;
  const east = ring.filter((pt) => pt[0] >= 0).length >= ring.length / 2;
  return ring.map(([lon, lat]) => [east && lon < 0 ? lon + 360 : !east && lon > 0 ? lon - 360 : lon, lat]);
}

function ringPath(ring: number[][], w: number, h: number): string {
  return (
    unwrap(ring)
      .map((pt, i) => {
        const [x, y] = project(pt[0], pt[1], w, h);
        return `${i === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`;
      })
      .join(" ") + " Z"
  );
}

function featurePath(f: Feature, w: number, h: number): string {
  const g = f.geometry;
  if (g.type === "Polygon") {
    return (g.coordinates as number[][][]).map((ring) => ringPath(ring, w, h)).join(" ");
  }
  return (g.coordinates as number[][][][]).map((poly) => poly.map((ring) => ringPath(ring, w, h)).join(" ")).join(" ");
}

function fillFor(count: number, max: number): string {
  if (count <= 0 || max <= 0) return "var(--panel-2)";
  const t = Math.max(0.18, Math.min(1, Math.log10(count + 1) / Math.log10(max + 1)));
  return `rgb(var(--accent-rgb) / ${t.toFixed(3)})`;
}

// Hovering a country shows its count and share; onSelect makes countries
// with traffic clickable (the ranked list below the map is the keyboard path).
export function CountryMap({
  counts,
  missingMMDB,
  onSelect,
}: {
  counts: Record<string, number>;
  missingMMDB?: boolean;
  onSelect?: (iso: string) => void;
}) {
  const w = 860;
  const h = 430;
  const box = useRef<HTMLDivElement>(null);
  const [tip, setTip] = useState<{ iso: string; x: number; y: number } | null>(null);
  const max = Math.max(0, ...Object.values(counts));
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (missingMMDB) {
    return (
      <p className="mt-4 text-sm text-dim">
        GeoIP is not loaded. Country allow/deny fails closed; the map has
        nothing to plot. Images ship a DB-IP Country Lite file at{" "}
        <span className="mono">/usr/share/aegis/geoip/country.mmdb</span>. Set{" "}
        <span className="mono">AEGIS_GEOIP_MMDB</span> to that path, or{" "}
        <span className="mono">none</span> to disable.
      </p>
    );
  }
  if (max === 0) {
    return (
      <div className="mt-4">
        <p className="text-sm text-dim">No country samples in this range yet.</p>
        <DbipCredit />
      </div>
    );
  }
  const n = tip ? (counts[tip.iso] ?? 0) : 0;
  const flip = tip && box.current ? tip.x > box.current.clientWidth * 0.6 : false;
  return (
    <div>
      <div ref={box} className="relative mt-3" onPointerLeave={() => setTip(null)}>
        <svg viewBox={`0 0 ${w} ${h}`} className="w-full overflow-hidden" role="img" aria-label="Requests by country">
          <rect width={w} height={h} fill="var(--bg-elev)" />
          {collection.features.map((f) => {
            const iso = f.properties.iso;
            const c = counts[iso] ?? 0;
            const hot = tip?.iso === iso;
            return (
              <path
                key={iso}
                d={featurePath(f, w, h)}
                fill={fillFor(c, max)}
                stroke={hot ? "var(--text)" : "var(--border)"}
                strokeWidth={hot ? 1.2 : 0.4}
                style={{ cursor: onSelect && c > 0 ? "pointer" : undefined }}
                onPointerMove={(e) => {
                  const r = box.current?.getBoundingClientRect();
                  if (r) setTip({ iso, x: e.clientX - r.left, y: e.clientY - r.top });
                }}
                onClick={onSelect && c > 0 ? () => onSelect(iso) : undefined}
              />
            );
          })}
        </svg>
        {tip && (
          <div
            className="pointer-events-none absolute z-10 min-w-[11rem] rounded-xl border border-border-strong bg-panel/95 px-3 py-2 text-xs shadow-xl backdrop-blur"
            style={{
              left: tip.x,
              top: tip.y,
              transform: `translate(${flip ? "calc(-100% - 14px)" : "14px"}, -50%)`,
            }}
          >
            <div className="flex items-center gap-2 font-semibold">
              <span className="rounded-md border border-border-strong bg-panel-2 px-1.5 font-mono text-[11px] text-dim">{tip.iso}</span>
              {countryName(tip.iso)}
            </div>
            <div className="mt-1 flex justify-between gap-4 text-dim">
              <span>Requests</span>
              <span className="font-mono text-fg">
                {fmtInt(n)}
                {total > 0 && n > 0 ? ` · ${((n / total) * 100).toFixed(1)}%` : ""}
              </span>
            </div>
            {onSelect && n > 0 && <div className="mt-1 text-[11px] text-accent">Click to open these requests</div>}
          </div>
        )}
      </div>
      <DbipCredit />
    </div>
  );
}

function DbipCredit() {
  return (
    <p className="mt-2 text-xs text-faint">
      IP Geolocation by{" "}
      <a href="https://db-ip.com" className="underline decoration-border hover:text-fg" rel="noopener noreferrer">
        DB-IP
      </a>
    </p>
  );
}

export function geoCounts(rows: { country?: string; key?: string; count: number }[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of rows) {
    const cc = (r.country || r.key || "").toUpperCase();
    if (!cc) continue;
    out[cc] = (out[cc] || 0) + Number(r.count || 0);
  }
  return out;
}
