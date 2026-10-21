// Shared shaping of persisted analytics rollups for Overview and Analytics.

import type { RollupRow } from "@/lib/types";
import type { SeriesPoint } from "@/components/charts";
import { fmtBucket } from "@/lib/format";

export function rollupTotals(rows: RollupRow[]) {
  let total = 0;
  let blocked = 0;
  for (const r of rows) {
    const n = Number(r.count) || 0;
    total += n;
    if (r.block_stage) blocked += n;
  }
  return { total, blocked };
}

// Blocked counts per stage, largest first.
export function rollupStages(rows: RollupRow[]) {
  const by: Record<string, number> = {};
  for (const r of rows) {
    if (!r.block_stage) continue;
    by[r.block_stage] = (by[r.block_stage] || 0) + (Number(r.count) || 0);
  }
  return Object.entries(by)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count);
}

const HOUR = 3600_000;
const DAY = 24 * HOUR;

function emptyPoint(start: number, span: number, daily: boolean): SeriesPoint {
  return { label: fmtBucket(start, daily), ok: 0, blocked: 0, start, end: start + span, stages: {}, latSum: 0, errors: 0, bytes: 0 };
}

// Adds a rollup row to its point: served/blocked, per-stage counts, the
// latency and 5xx count of served requests (blocked ones never reached an
// upstream), and bytes sent to clients either way.
function addRow(p: SeriesPoint, r: RollupRow) {
  const n = Number(r.count) || 0;
  p.bytes! += Number(r.bytes_sum) || 0;
  if (r.block_stage) {
    p.blocked += n;
    p.stages![r.block_stage] = (p.stages![r.block_stage] || 0) + n;
  } else {
    p.ok += n;
    p.latSum! += Number(r.latency_sum_ms) || 0;
    if (Number(r.status_class) === 5) p.errors! += n;
  }
}

// One chart point per bucket, oldest first. Daily buckets label by day.
export function rollupSeries(rows: RollupRow[], daily = false): SeriesPoint[] {
  const by: Record<string, SeriesPoint> = {};
  for (const r of rows) {
    const t = new Date(r.bucket_start).getTime();
    const key = String(t);
    by[key] ??= emptyPoint(t, daily ? DAY : HOUR, daily);
    addRow(by[key], r);
  }
  return Object.values(by).sort((a, b) => a.start! - b.start!);
}

// Display name for a pipeline stage key from telemetry.
export function stageLabel(s: string) {
  switch (s) {
    case "waf":
      return "WAF";
    case "crowdsec":
      return "CrowdSec";
    case "ratelimit":
      return "Rate limit";
    case "geo":
      return "GeoIP";
    case "acl":
      return "ACL";
    default:
      return s || "—";
  }
}

// Start (ms) of the window of `n` buckets that ends with the one holding
// `now`. Daily buckets start at UTC midnight.
export function windowStart(n: number, daily = false, now = Date.now()): number {
  const span = daily ? DAY : HOUR;
  return Math.floor(now / span) * span - (n - 1) * span;
}

// How far into its bucket `now` is, 0–1: the share of the window's last
// bucket that has happened so far.
export function bucketElapsed(daily = false, now = Date.now()): number {
  const span = daily ? DAY : HOUR;
  return (now - Math.floor(now / span) * span) / span;
}

// One point per bucket for the `n` buckets ending with the one that holds
// `now`, empty ones included, so a quiet install still draws a timeline.
// Rows outside the window are ignored.
export function seriesFilled(rows: RollupRow[], n: number, daily = false, now = Date.now()): SeriesPoint[] {
  const span = daily ? DAY : HOUR;
  const start = windowStart(n, daily, now);
  const end = start + (n - 1) * span;
  const pts: SeriesPoint[] = [];
  for (let t = start; t <= end; t += span) pts.push(emptyPoint(t, span, daily));
  for (const r of rows) {
    const t = Math.floor(new Date(r.bucket_start).getTime() / span) * span;
    const i = (t - start) / span;
    if (i < 0 || i >= pts.length) continue;
    addRow(pts[i], r);
  }
  return pts;
}

// Hourly served/blocked for the last `hours` hours ending now.
export function hourlySeriesFilled(rows: RollupRow[], hours = 24, now = Date.now()): SeriesPoint[] {
  return seriesFilled(rows, hours, false, now);
}

export type PeriodTotals = {
  served: number;
  blocked: number;
  // Served requests the upstream answered with a 5xx.
  errors: number;
  bytes: number;
  // Average latency of served requests.
  avgMs: number | null;
};

// Totals over the points. lastShare (0–1) counts only that share of the last
// point: the current window ends in a bucket that is still filling, so the
// window before is cut at the same point in its last bucket (assuming even
// traffic inside it) to compare equal stretches of time.
export function seriesTotals(points: SeriesPoint[], lastShare = 1): PeriodTotals {
  let served = 0;
  let blocked = 0;
  let errors = 0;
  let bytes = 0;
  let latSum = 0;
  points.forEach((p, i) => {
    const w = i === points.length - 1 ? lastShare : 1;
    served += p.ok * w;
    blocked += p.blocked * w;
    errors += (p.errors ?? 0) * w;
    bytes += (p.bytes ?? 0) * w;
    latSum += (p.latSum ?? 0) * w;
  });
  return { served, blocked, errors, bytes, avgMs: served > 0 ? latSum / served : null };
}

export type HostStats = {
  hostID: string;
  domain: string;
  served: number;
  blocked: number;
  errors: number;
  avgMs: number | null;
};

// Per-host totals over rollup rows, busiest first. The rows are already
// scoped to the range (the API's group=host rows, or stored rows).
export function hostStats(rows: RollupRow[]): HostStats[] {
  const by: Record<string, HostStats & { latSum: number }> = {};
  for (const r of rows) {
    if (!r.host_id) continue;
    const h = (by[r.host_id] ??= { hostID: r.host_id, domain: r.domain, served: 0, blocked: 0, errors: 0, avgMs: null, latSum: 0 });
    const n = Number(r.count) || 0;
    if (r.block_stage) h.blocked += n;
    else {
      h.served += n;
      h.latSum += Number(r.latency_sum_ms) || 0;
      if (Number(r.status_class) === 5) h.errors += n;
    }
  }
  return Object.values(by)
    .map(({ latSum, ...h }) => ({ ...h, avgMs: h.served > 0 ? latSum / h.served : null }))
    .sort((a, b) => b.served + b.blocked - (a.served + a.blocked));
}

export type HostTraffic = {
  requests: number;
  blocked: number;
  avgMs: number | null;
  // Requests per hour, oldest first, `hours` long.
  hourly: number[];
  // Requests per second over the last full hour, or over the current hour
  // so far when the last full hour was empty.
  rps: number;
};

// Per-host traffic from hourly rollups over the last `hours` hours.
export function trafficByHost(rows: RollupRow[], hours = 24, now = Date.now()): Record<string, HostTraffic> {
  const end = Math.floor(now / HOUR) * HOUR;
  const start = end - (hours - 1) * HOUR;
  const out: Record<string, HostTraffic & { latSum: number; latN: number }> = {};
  for (const r of rows) {
    if (!r.host_id) continue;
    const h = (out[r.host_id] ??= { requests: 0, blocked: 0, avgMs: null, hourly: Array(hours).fill(0), rps: 0, latSum: 0, latN: 0 });
    const n = Number(r.count) || 0;
    h.requests += n;
    if (r.block_stage) h.blocked += n;
    else {
      h.latSum += Number(r.latency_sum_ms) || 0;
      h.latN += n;
    }
    const t = Math.floor(new Date(r.bucket_start).getTime() / HOUR) * HOUR;
    const i = (t - start) / HOUR;
    if (i >= 0 && i < hours) h.hourly[i] += n;
  }
  const res: Record<string, HostTraffic> = {};
  for (const [id, h] of Object.entries(out)) {
    const lastFull = h.hourly[hours - 2] ?? 0;
    const elapsed = Math.max(60, (now - end) / 1000);
    res[id] = {
      requests: h.requests,
      blocked: h.blocked,
      avgMs: h.latN > 0 ? h.latSum / h.latN : null,
      hourly: h.hourly,
      rps: lastFull > 0 ? lastFull / 3600 : (h.hourly[hours - 1] ?? 0) / elapsed,
    };
  }
  return res;
}
