"use client";

import { KeyboardEvent, PointerEvent, useId, useRef, useState } from "react";
import { fmtInt, fmtLatency } from "@/lib/format";
import { stageLabel } from "@/lib/rollups";

// A chart bucket. start/end (ms) bound it; stages splits `blocked` by layer;
// latSum is the summed latency of the served requests, errors how many of
// them the upstream answered with a 5xx, bytes what was sent to clients.
export type SeriesPoint = {
  label: string;
  ok: number;
  blocked: number;
  start?: number;
  end?: number;
  stages?: Record<string, number>;
  latSum?: number;
  errors?: number;
  bytes?: number;
};

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const pad2 = (n: number) => String(n).padStart(2, "0");

// "Thu, Sep 24 · 14:00–15:00" for an hour, "Thu, Sep 24" for a day.
function bucketTitle(p: SeriesPoint): string {
  if (p.start === undefined) return p.label;
  const a = new Date(p.start);
  if (p.end !== undefined && p.end - p.start >= 864e5) {
    return `${WEEKDAYS[a.getUTCDay()]}, ${MONTHS[a.getUTCMonth()]} ${a.getUTCDate()} (UTC day)`;
  }
  const day = `${WEEKDAYS[a.getDay()]}, ${MONTHS[a.getMonth()]} ${a.getDate()}`;
  const b = new Date(p.end ?? p.start + 3600_000);
  return `${day} · ${pad2(a.getHours())}:${pad2(a.getMinutes())}–${pad2(b.getHours())}:${pad2(b.getMinutes())}`;
}

// Served vs blocked over time. The SVG stretches to the container width at a
// fixed pixel height, so strokes use non-scaling-stroke and axis labels live
// in HTML; otherwise a wide screen would scale the labels with it.
//
// Hovering (or arrow keys when focused) shows the bucket's time and numbers;
// onSelect makes a bucket clickable (open its requests). `previous` is the
// period before, bucket for bucket, drawn as a dotted line to compare with.
export function TimeSeriesChart({
  points,
  previous,
  height = 200,
  onSelect,
}: {
  points: SeriesPoint[];
  previous?: SeriesPoint[];
  height?: number;
  onSelect?: (p: SeriesPoint) => void;
}) {
  const gid = useId().replace(/:/g, "");
  const wrap = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  if (points.length === 0) {
    return <p className="mt-4 text-sm text-dim">No samples in this range yet.</p>;
  }
  const w = 640;
  const h = height;
  const padT = 10;
  const innerH = h - padT;
  const total = points.map((p) => p.ok + p.blocked);
  const blocked = points.map((p) => p.blocked);
  const n = points.length;
  // Only comparable when it lines up bucket for bucket and has any traffic.
  const prev =
    previous && previous.length === n && previous.some((p) => p.ok + p.blocked > 0) ? previous.map((p) => p.ok + p.blocked) : null;
  const max = Math.max(1, ...total, ...(prev ?? [])) * 1.08;
  const xAt = (i: number) => (n === 1 ? w / 2 : (i / (n - 1)) * w);
  const yAt = (v: number) => padT + innerH - (v / max) * innerH;

  function line(vals: number[]) {
    return vals.map((v, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)} ${yAt(v).toFixed(1)}`).join(" ");
  }
  function area(vals: number[]) {
    return `${line(vals)} L${xAt(n - 1).toFixed(1)} ${h} L${xAt(0).toFixed(1)} ${h} Z`;
  }
  const ticks = [0, Math.floor((n - 1) / 4), Math.floor((n - 1) / 2), Math.floor(((n - 1) * 3) / 4), n - 1].filter(
    (i, idx, a) => a.indexOf(i) === idx,
  );
  const colW = 18;

  function indexAt(clientX: number) {
    const r = wrap.current?.getBoundingClientRect();
    if (!r || r.width === 0 || n === 1) return 0;
    return Math.max(0, Math.min(n - 1, Math.round(((clientX - r.left) / r.width) * (n - 1))));
  }
  function onMove(e: PointerEvent<HTMLDivElement>) {
    setHover(indexAt(e.clientX));
  }
  function onKey(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      setHover((cur) => {
        const at = cur ?? n - 1;
        return Math.max(0, Math.min(n - 1, at + (e.key === "ArrowLeft" ? -1 : 1)));
      });
    } else if ((e.key === "Enter" || e.key === " ") && hover !== null && onSelect) {
      e.preventDefault();
      onSelect(points[hover]);
    } else if (e.key === "Escape") {
      setHover(null);
    }
  }

  const hp = hover !== null ? points[hover] : null;
  const leftPct = hover !== null ? (xAt(hover) / w) * 100 : 0;
  const clickable = !!onSelect && !!hp && hp.ok + hp.blocked > 0;

  return (
    <div>
      <div
        ref={wrap}
        className={`relative rounded-md outline-none focus-visible:ring-2 focus-visible:ring-accent/60 ${clickable ? "cursor-pointer" : ""}`}
        tabIndex={0}
        role="group"
        aria-label={`Served and blocked requests over time, ${n} buckets. Use the arrow keys to read each one${onSelect ? " and Enter to open its requests" : ""}.`}
        onPointerMove={onMove}
        onPointerLeave={() => setHover(null)}
        onFocus={() => setHover((cur) => cur ?? n - 1)}
        onBlur={() => setHover(null)}
        onKeyDown={onKey}
        onClick={(e) => {
          if (!onSelect) return;
          const p = points[indexAt(e.clientX)];
          if (p.ok + p.blocked > 0) onSelect(p);
        }}
      >
        <svg
          viewBox={`0 0 ${w} ${h}`}
          preserveAspectRatio="none"
          className="block w-full"
          style={{ height: h }}
          aria-hidden="true"
        >
          <defs>
            <linearGradient id={`${gid}-ok`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="var(--accent)" stopOpacity="0.32" />
              <stop offset="1" stopColor="var(--accent)" stopOpacity="0" />
            </linearGradient>
            <linearGradient id={`${gid}-bad`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="var(--danger)" stopOpacity="0.5" />
              <stop offset="1" stopColor="var(--danger)" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map((f) => (
            <line
              key={f}
              x1="0"
              x2={w}
              y1={h * f}
              y2={h * f}
              stroke="var(--border)"
              strokeDasharray="3 5"
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {n === 1 ? (
            // One bucket has no line to draw: show it as a column.
            <>
              <rect x={w / 2 - colW / 2} y={yAt(total[0])} width={colW} height={yAt(0) - yAt(total[0])} rx="3" fill="var(--accent)" fillOpacity="0.45" />
              <rect x={w / 2 - colW / 2} y={yAt(blocked[0])} width={colW} height={yAt(0) - yAt(blocked[0])} rx="3" fill="var(--danger)" fillOpacity="0.85" />
            </>
          ) : (
            <>
              <path d={area(total)} fill={`url(#${gid}-ok)`} />
              <path d={area(blocked)} fill={`url(#${gid}-bad)`} />
              {/* After both fills, so a lower period before is not lost under them. */}
              {prev && (
                <path d={line(prev)} fill="none" stroke="var(--text-faint)" strokeWidth="1.5" strokeDasharray="2 4" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
              )}
              <path d={line(total)} fill="none" stroke="var(--accent)" strokeWidth="2.25" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
              <path d={line(blocked)} fill="none" stroke="var(--danger)" strokeWidth="2" strokeDasharray="6 3" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
            </>
          )}
        </svg>
        {hp && hover !== null && (
          <>
            <div aria-hidden className="pointer-events-none absolute inset-y-0 w-px bg-border-strong" style={{ left: `${leftPct}%` }} />
            <span
              aria-hidden
              className="pointer-events-none absolute h-2.5 w-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-bg bg-accent"
              style={{ left: `${leftPct}%`, top: yAt(total[hover]) }}
            />
            {hp.blocked > 0 && (
              <span
                aria-hidden
                className="pointer-events-none absolute h-2.5 w-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-bg bg-danger"
                style={{ left: `${leftPct}%`, top: yAt(blocked[hover]) }}
              />
            )}
            <ChartTooltip point={hp} previous={prev ? prev[hover] : undefined} leftPct={leftPct} hint={clickable ? "Click to open these requests" : undefined} />
          </>
        )}
      </div>
      <p className="sr-only" aria-live="polite">
        {hp
          ? `${bucketTitle(hp)}: ${fmtInt(hp.ok)} served, ${fmtInt(hp.blocked)} blocked${prev && hover !== null ? `, ${fmtInt(prev[hover])} in the period before` : ""}`
          : ""}
      </p>
      <div className="relative mt-2 h-4 font-mono text-[11px] text-faint">
        {ticks.map((i) => (
          <span
            key={points[i].label + i}
            className="absolute top-0 whitespace-nowrap"
            style={{
              left: `${(xAt(i) / w) * 100}%`,
              transform: n === 1 || (i !== 0 && i !== n - 1) ? "translateX(-50%)" : i === n - 1 ? "translateX(-100%)" : undefined,
            }}
          >
            {points[i].label}
          </span>
        ))}
      </div>
    </div>
  );
}

function ChartTooltip({ point: p, previous, leftPct, hint }: { point: SeriesPoint; previous?: number; leftPct: number; hint?: string }) {
  const total = p.ok + p.blocked;
  const stages = Object.entries(p.stages ?? {}).sort((a, b) => b[1] - a[1]);
  const avg = p.ok > 0 && p.latSum !== undefined ? p.latSum / p.ok : null;
  // Flip to the left of the guide past the middle so it stays on the card.
  const flip = leftPct > 55;
  return (
    <div
      className="pointer-events-none absolute top-2 z-10 w-56 rounded-xl border border-border-strong bg-panel/95 p-3 text-xs shadow-xl backdrop-blur"
      style={{ left: `${leftPct}%`, transform: flip ? "translateX(calc(-100% - 12px))" : "translateX(12px)" }}
    >
      <div className="font-semibold text-fg">{bucketTitle(p)}</div>
      <dl className="mt-2 space-y-1">
        <TipRow swatch="border-accent" label="Served" value={fmtInt(p.ok)} />
        <TipRow
          swatch="border-dashed border-danger"
          label="Blocked"
          value={`${fmtInt(p.blocked)}${total > 0 && p.blocked > 0 ? ` · ${((p.blocked / total) * 100).toFixed(1)}%` : ""}`}
        />
        {stages.map(([k, v]) => (
          <div key={k} className="flex justify-between pl-5 text-faint">
            <dt>{stageLabel(k)}</dt>
            <dd className="font-mono">{fmtInt(v)}</dd>
          </div>
        ))}
        <div className="flex justify-between border-t border-border pt-1">
          <dt className="text-dim">Total</dt>
          <dd className="font-mono">{fmtInt(total)}</dd>
        </div>
        {previous !== undefined && <TipRow swatch="border-dotted border-faint" label="Period before" value={fmtInt(previous)} />}
        {avg !== null && (
          <div className="flex justify-between">
            <dt className="text-dim">Avg latency</dt>
            <dd className="font-mono">{fmtLatency(avg)}</dd>
          </div>
        )}
      </dl>
      {hint && <div className="mt-2 text-[11px] text-accent">{hint}</div>}
    </div>
  );
}

function TipRow({ swatch, label, value }: { swatch: string; label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="flex items-center gap-2 text-dim">
        <span aria-hidden className={`inline-block w-3 border-t-[2.5px] ${swatch}`} />
        {label}
      </dt>
      <dd className="font-mono text-fg">{value}</dd>
    </div>
  );
}

// Legend for TimeSeriesChart; the blocked swatch is dashed like its line so
// the series are distinguishable without colour. `previous` names the
// comparison line when the chart draws one.
export function ServedBlockedLegend({ previous }: { previous?: string }) {
  return (
    <div className="flex items-center gap-4 text-xs font-medium text-dim">
      <span className="inline-flex items-center gap-2">
        <span aria-hidden className="inline-block w-3.5 border-t-[2.5px] border-accent" /> Served
      </span>
      <span className="inline-flex items-center gap-2">
        <span aria-hidden className="inline-block w-3.5 border-t-[2.5px] border-dashed border-danger" /> Blocked
      </span>
      {previous && (
        <span className="inline-flex items-center gap-2">
          <span aria-hidden className="inline-block w-3.5 border-t-[2.5px] border-dotted border-faint" /> {previous}
        </span>
      )}
    </div>
  );
}

// Tiny trend line for tables and cards. Flat when every value is equal.
export function Sparkline({
  values,
  width = 96,
  height = 26,
  color = "var(--accent)",
  label,
}: {
  values: number[];
  width?: number;
  height?: number;
  color?: string;
  label?: string;
}) {
  if (values.length < 2) {
    return <svg width={width} height={height} aria-hidden="true" />;
  }
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = max - min || 1;
  const d = values
    .map((v, i) => {
      const x = (i / (values.length - 1)) * width;
      const y = max === min ? height / 2 : height - 2 - ((v - min) / span) * (height - 4);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      className="block"
      style={{ width: "100%", maxWidth: width, height }}
    >
      <path d={d} fill="none" stroke={color} strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

// Ring gauge for the posture score (0–100).
export function ScoreRing({ score, size = 156, stroke = 12, label }: { score: number; size?: number; stroke?: number; label: string }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const clamped = Math.max(0, Math.min(100, score));
  const tone = clamped >= 80 ? "var(--ok)" : clamped >= 50 ? "var(--warn)" : "var(--danger)";
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label} className="shrink-0">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border-strong)" strokeWidth={stroke} />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={r}
        fill="none"
        stroke={tone}
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeDasharray={`${((c * clamped) / 100).toFixed(1)} ${c.toFixed(1)}`}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
        style={{ transition: "stroke-dasharray .6s ease" }}
      />
      <text x="50%" y="47%" textAnchor="middle" dominantBaseline="middle" fill="var(--text)" fontFamily="var(--font-display)" fontSize={size * 0.28} fontWeight="700">
        {Math.round(clamped)}
      </text>
      <text x="50%" y="68%" textAnchor="middle" fill="var(--text-faint)" fontFamily="var(--font-sans)" fontSize="12">
        of 100
      </text>
    </svg>
  );
}

// Palette for categorical slices (stages). Same order everywhere so a stage
// keeps its colour between the donut and any list next to it.
export const STAGE_COLORS: Record<string, string> = {
  waf: "var(--series-1)",
  crowdsec: "var(--series-2)",
  geo: "var(--series-3)",
  ratelimit: "var(--series-4)",
  acl: "var(--series-5)",
};
const FALLBACK = ["var(--series-1)", "var(--series-2)", "var(--series-3)", "var(--series-4)", "var(--series-5)", "var(--text-dim)"];

export function stageColor(key: string, i: number) {
  return STAGE_COLORS[key] ?? FALLBACK[i % FALLBACK.length];
}

// Donut of blocked requests by stage with a total in the middle and a legend
// beside it (the legend carries the numbers, so colour is not the only cue).
// Hovering a slice or legend row shows that layer in the middle; onSelect
// makes the legend rows open that layer's requests.
export function StageDonut({
  rows,
  empty,
  size = 150,
  stroke = 18,
  onSelect,
}: {
  rows: { key: string; count: number }[];
  empty: string;
  size?: number;
  stroke?: number;
  onSelect?: (key: string) => void;
}) {
  const [active, setActive] = useState<string | null>(null);
  const total = rows.reduce((s, r) => s + r.count, 0);
  if (total === 0) return <p className="mt-4 text-sm text-dim">{empty}</p>;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  let off = 0;
  const cur = rows.find((row) => row.key === active);
  return (
    <div className="mt-4 flex flex-wrap items-center gap-6">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Blocked requests by layer, ${fmtInt(total)} total`} className="shrink-0">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--panel-2)" strokeWidth={stroke} />
        {rows.map((row, i) => {
          const seg = (c * row.count) / total;
          const gap = rows.length > 1 && seg > 4 ? 3 : 0;
          const el = (
            <circle
              key={row.key}
              cx={size / 2}
              cy={size / 2}
              r={r}
              fill="none"
              stroke={stageColor(row.key, i)}
              strokeWidth={active === row.key ? stroke + 4 : stroke}
              strokeOpacity={active && active !== row.key ? 0.35 : 1}
              strokeDasharray={`${Math.max(seg - gap, 0.5).toFixed(1)} ${c.toFixed(1)}`}
              strokeDashoffset={(-off).toFixed(1)}
              transform={`rotate(-90 ${size / 2} ${size / 2})`}
              style={{ transition: "stroke-opacity .15s, stroke-width .15s", cursor: onSelect ? "pointer" : undefined }}
              onPointerEnter={() => setActive(row.key)}
              onPointerLeave={() => setActive(null)}
              onClick={onSelect ? () => onSelect(row.key) : undefined}
            />
          );
          off += seg;
          return el;
        })}
        <text x="50%" y="46%" textAnchor="middle" dominantBaseline="middle" fill="var(--text)" fontFamily="var(--font-display)" fontSize="24" fontWeight="700">
          {compact(cur ? cur.count : total)}
        </text>
        <text x="50%" y="63%" textAnchor="middle" fill="var(--text-faint)" fontFamily="var(--font-sans)" fontSize="11">
          {cur ? `${stageLabel(cur.key)} · ${Math.round((cur.count / total) * 100)}%` : "blocked"}
        </text>
      </svg>
      <ul className="min-w-[12rem] flex-1 space-y-1">
        {rows.map((row, i) => {
          const body = (
            <>
              <span aria-hidden className="h-2.5 w-2.5 shrink-0 rounded-[3px]" style={{ background: stageColor(row.key, i) }} />
              <span>{stageLabel(row.key)}</span>
              <span className="ml-auto font-mono text-xs text-dim">{fmtInt(row.count)}</span>
              <span className="w-10 text-right font-mono text-xs text-faint">{Math.round((row.count / total) * 100)}%</span>
            </>
          );
          const cls = `flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left text-sm transition-colors ${
            active === row.key ? "bg-panel-2" : ""
          }`;
          return (
            <li key={row.key} onPointerEnter={() => setActive(row.key)} onPointerLeave={() => setActive(null)}>
              {onSelect ? (
                <button
                  type="button"
                  className={`${cls} hover:bg-panel-2`}
                  onFocus={() => setActive(row.key)}
                  onBlur={() => setActive(null)}
                  onClick={() => onSelect(row.key)}
                  aria-label={`${stageLabel(row.key)}: ${fmtInt(row.count)} blocked. Open these requests`}
                >
                  {body}
                </button>
              ) : (
                <div className={cls}>{body}</div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function compact(n: number) {
  if (n < 10_000) return fmtInt(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 100_000 ? 1 : 0).replace(/\.0$/, "")}k`;
  return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
}

// Horizontal bars (latency histogram and similar).
export function BarChart({
  rows,
  color = "var(--accent)",
}: {
  rows: { label: string; count: number }[];
  color?: string;
}) {
  if (rows.length === 0) {
    return <p className="mt-4 text-sm text-dim">No samples yet.</p>;
  }
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <div className="mt-4 space-y-2">
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-3 text-xs">
          <span className="w-16 truncate text-right font-mono text-faint">{r.label}</span>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-panel-2">
            <div className="h-full rounded-full" style={{ width: `${Math.max(2, (r.count / max) * 100)}%`, background: color }} />
          </div>
          <span className="w-12 font-mono text-dim">{fmtInt(r.count)}</span>
        </div>
      ))}
    </div>
  );
}

// Blocked requests per pipeline stage (WAF, ACL, CrowdSec, …), largest first.
// onSelect makes each row open that stage's requests.
export function StageBars({
  rows,
  empty,
  onSelect,
}: {
  rows: { key: string; count: number }[];
  empty: string;
  onSelect?: (key: string) => void;
}) {
  if (rows.length === 0) {
    return <p className="mt-4 text-sm text-dim">{empty}</p>;
  }
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <div className="mt-3 space-y-1">
      {rows.map((s, i) => {
        const body = (
          <>
            <div className="flex justify-between text-sm">
              <span>{stageLabel(s.key)}</span>
              <span className="font-mono text-xs text-dim">{fmtInt(s.count)}</span>
            </div>
            <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-panel-2">
              <div className="h-full rounded-full" style={{ width: `${Math.max(3, (s.count / max) * 100)}%`, background: stageColor(s.key, i) }} />
            </div>
          </>
        );
        return onSelect ? (
          <button
            key={s.key}
            type="button"
            className="block w-full rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-panel-2"
            onClick={() => onSelect(s.key)}
            aria-label={`${stageLabel(s.key)}: ${fmtInt(s.count)} blocked. Open these requests`}
          >
            {body}
          </button>
        ) : (
          <div key={s.key} className="px-2 py-1.5">
            {body}
          </div>
        );
      })}
    </div>
  );
}
