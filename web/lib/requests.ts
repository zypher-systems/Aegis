// Request log filters, the links that open the Requests explorer with them,
// and how a single request's outcome is described everywhere.

import type { AnalyticsEvent } from "@/lib/types";
import type { Tone } from "@/components/ui";
import { stageLabel } from "@/lib/rollups";

export type RequestRange = "1h" | "24h" | "7d" | "30d" | "custom";

export type RequestFilters = {
  range: RequestRange;
  // ISO times; only used when range is "custom" (a chart bucket).
  from?: string;
  to?: string;
  host_id?: string;
  country?: string;
  ip?: string;
  stage?: string;
  outcome?: "" | "blocked" | "flagged" | "served";
  rule?: string;
  status?: string; // status class "2".."5"
  method?: string;
  path?: string; // exact
  q?: string;
};

export const RANGE_MS: Record<Exclude<RequestRange, "custom">, number> = {
  "1h": 3600_000,
  "24h": 864e5,
  "7d": 7 * 864e5,
  "30d": 30 * 864e5,
};

const KEYS = ["from", "to", "host_id", "country", "ip", "stage", "outcome", "rule", "status", "method", "path", "q"] as const;

export function filtersFromSearch(search: string): RequestFilters {
  const p = new URLSearchParams(search);
  const f: RequestFilters = { range: "24h" };
  const r = p.get("range");
  if (r === "1h" || r === "24h" || r === "7d" || r === "30d") f.range = r;
  for (const k of KEYS) {
    const v = p.get(k);
    if (v) (f as Record<string, string>)[k] = v;
  }
  if (f.from || f.to) f.range = "custom";
  return f;
}

export function filtersToSearch(f: RequestFilters): string {
  const p = new URLSearchParams();
  if (f.range !== "24h" && f.range !== "custom") p.set("range", f.range);
  for (const k of KEYS) {
    if ((k === "from" || k === "to") && f.range !== "custom") continue;
    const v = f[k];
    if (v) p.set(k, v);
  }
  return p.toString();
}

// Link to the Analytics → Requests tab with these filters applied.
export function requestsHref(f: Partial<RequestFilters>): string {
  const qs = filtersToSearch({ range: "24h", ...f });
  return `/analytics${qs ? `?${qs}` : ""}#requests`;
}

// Query for GET /api/analytics/requests.
export function apiParams(f: RequestFilters, now = Date.now()): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {
    host_id: f.host_id,
    country: f.country,
    ip: f.ip,
    stage: f.stage,
    outcome: f.outcome,
    rule: f.rule,
    status: f.status,
    method: f.method,
    path: f.path,
    q: f.q,
  };
  if (f.range === "custom") {
    out.from = f.from;
    out.to = f.to;
  } else {
    out.from = new Date(now - RANGE_MS[f.range]).toISOString();
  }
  return out;
}

export type Outcome = { tone: Tone; label: string; short: string };

// Blocked (a stage stopped it), flagged (the WAF matched in Detect mode) or
// served. `short` fits a table cell: "WAF · 942100".
export function outcomeOf(e: AnalyticsEvent): Outcome {
  if (e.block_stage) {
    const stage = stageLabel(e.block_stage);
    const bits = [stage];
    if (e.block_stage === "waf" && e.waf_rule_id) bits.push(e.waf_rule_id);
    if (e.block_stage === "crowdsec" && e.crowdsec_origin) bits.push(e.crowdsec_origin);
    return { tone: "danger", label: `Blocked by ${stage}`, short: bits.join(" · ") };
  }
  if (e.waf_action) {
    const bits = ["WAF detect"];
    if (e.waf_rule_id) bits.push(e.waf_rule_id);
    return { tone: "warn", label: "Flagged by the WAF (Detect mode), then served", short: bits.join(" · ") };
  }
  return { tone: "ok", label: "Served", short: "—" };
}

// Colour only reinforces the code, which is always printed.
export function statusTone(status?: number): Tone {
  if (!status) return "neutral";
  if (status >= 500) return "danger";
  if (status >= 400) return "warn";
  if (status >= 300) return "neutral";
  return "ok";
}

export function severityLabel(sev: number): { label: string; tone: Tone } {
  switch (sev) {
    case 0:
    case 1:
    case 2:
      return { label: "Critical", tone: "danger" };
    case 3:
      return { label: "Error", tone: "danger" };
    case 4:
      return { label: "Warning", tone: "warn" };
    default:
      return { label: "Notice", tone: "neutral" };
  }
}

// REQUEST_COOKIES:session, the form a WAF exclusion's "Only this input" takes.
export function matchTarget(m: { variable?: string; key?: string }): string {
  if (!m.variable) return "";
  return m.key ? `${m.variable}:${m.key}` : m.variable;
}

export function fmtBytes(n?: number): string {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// 2026-09-24 14:47:21.948 in local time.
export function fmtFullTime(ms?: number): string {
  if (!ms) return "—";
  const d = new Date(ms);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}
