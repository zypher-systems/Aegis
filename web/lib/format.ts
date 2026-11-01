// One place for how the dashboard prints dates and numbers.
//
// Dates:  2026-09-23 17:20       fmtDateTime
//         2026-09-23             fmtDate
//         17:20:31               fmtTime (live feeds)
//         17:00 / Sep 23         fmtBucket (chart axes)
//         in 3d / 16d ago        fmtRelative
// Local time, 24-hour, ISO-ordered dates so columns line up and sort by eye.

type DateInput = string | number | Date | null | undefined;

function toDate(v: DateInput): Date | null {
  if (v === null || v === undefined || v === "") return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

const pad = (n: number) => String(n).padStart(2, "0");

export function fmtDate(v: DateInput, empty = "—"): string {
  const d = toDate(v);
  if (!d) return empty;
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export function fmtTime(v: DateInput, empty = "—"): string {
  const d = toDate(v);
  if (!d) return empty;
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function fmtDateTime(v: DateInput, empty = "—"): string {
  const d = toDate(v);
  if (!d) return empty;
  return `${fmtDate(d)} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// Chart axis label for a rollup bucket: hour for hourly (local time), day
// for daily. Daily buckets start at UTC midnight, so they are named by their
// UTC date; a local date would be off by one west of Greenwich.
export function fmtBucket(v: DateInput, daily: boolean): string {
  const d = toDate(v);
  if (!d) return "";
  return daily ? `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}` : `${pad(d.getHours())}:00`;
}

// Coarse relative time: "just now", "5m ago", "in 3d".
export function fmtRelative(v: DateInput, now: number = Date.now(), empty = "never"): string {
  const d = toDate(v);
  if (!d) return empty;
  const diff = d.getTime() - now;
  const abs = Math.abs(diff);
  const s = Math.round(abs / 1000);
  if (s < 45) return "just now";
  const units: [number, string][] = [
    [60 * 60 * 24, "d"],
    [60 * 60, "h"],
    [60, "m"],
  ];
  let text = `${s}s`;
  for (const [size, unit] of units) {
    if (s >= size) {
      text = `${Math.floor(s / size)}${unit}`;
      break;
    }
  }
  return diff < 0 ? `${text} ago` : `in ${text}`;
}

// Whole days from now until v; negative when v is in the past.
export function daysUntil(v: DateInput, now: number = Date.now()): number | null {
  const d = toDate(v);
  if (!d) return null;
  return Math.floor((d.getTime() - now) / 86_400_000);
}

const intFmt = new Intl.NumberFormat("en-US");

export function fmtInt(n: number | null | undefined, empty = "—"): string {
  if (n === null || n === undefined || Number.isNaN(n)) return empty;
  return intFmt.format(Math.round(n));
}

// Compact counts for stat tiles: 1,234 / 12.3k / 4.5M.
export function fmtCount(n: number | null | undefined, empty = "—"): string {
  if (n === null || n === undefined || Number.isNaN(n)) return empty;
  if (Math.abs(n) < 10_000) return fmtInt(n);
  if (Math.abs(n) < 1_000_000) return `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k`;
  return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
}

// Byte totals for stat tiles, split so the unit can be set smaller:
// ["312", "GB"]. Binary multiples, like the per-request sizes.
export function fmtDataParts(n: number | null | undefined): [string, string] {
  if (n === null || n === undefined || Number.isNaN(n) || n <= 0) return ["0", "B"];
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return [v >= 100 || i === 0 ? String(Math.round(v)) : v.toFixed(1).replace(/\.0$/, ""), units[i]];
}

export function fmtMs(n: number | null | undefined, empty = "—"): string {
  if (n === null || n === undefined || Number.isNaN(n)) return empty;
  return n < 10 ? `${n.toFixed(2)} ms` : `${Math.round(n)} ms`;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${fmtInt(n)} ${n === 1 ? one : many}`;
}

// Whole-millisecond latency for summaries; sub-millisecond reads "<1 ms"
// rather than a misleading "0 ms".
export function fmtLatency(n: number | null | undefined, empty = "—"): string {
  if (n === null || n === undefined || Number.isNaN(n)) return empty;
  if (n < 1) return "<1 ms";
  return `${Math.round(n)} ms`;
}
