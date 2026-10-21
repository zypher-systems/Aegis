"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AlertTriangle, CheckCircle2, Plus, XCircle } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { api, isUnauthorized } from "@/lib/api";
import type {
  AnalyticsEvent,
  Certificate,
  CrowdSecStatus,
  Host,
  Node,
  Notice as NoticeItem,
  RollupRow,
} from "@/lib/types";
import { AppShell } from "@/components/app-shell";
import { LogoMark } from "@/components/logo";
import { ServedBlockedLegend, Sparkline, TimeSeriesChart } from "@/components/charts";
import { RequestDetail } from "@/components/request-detail";
import { ErrorState, Loading, Notice, PageHeader, StatusDot, Table } from "@/components/ui";
import { POLL_MS } from "@/lib/poll";
import { fmtCount, fmtDataParts, fmtDateTime, fmtInt, fmtLatency, fmtTime } from "@/lib/format";
import { bucketElapsed, hostStats, seriesFilled, seriesTotals, windowStart, type HostStats } from "@/lib/rollups";
import { outcomeOf, requestsHref } from "@/lib/requests";
import { computePosture, type CheckState, type Posture, type PostureCheck } from "@/lib/posture";

export default function Home() {
  const { user, loading, needsSetup } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (loading) return;
    if (needsSetup) router.replace("/setup");
    else if (!user) router.replace("/login");
  }, [user, loading, needsSetup, router]);

  if (loading || needsSetup || !user) {
    return (
      <div role="status" className="flex min-h-screen items-center justify-center">
        <LogoMark size={28} className="pulse" />
        <span className="sr-only">Loading Aegis</span>
      </div>
    );
  }

  return (
    <AppShell>
      <Overview />
    </AppShell>
  );
}

// The ranges read persisted rollups: hourly buckets for a day, daily beyond.
// `before` names the period each figure is compared with.
type RangeKey = "24h" | "7d" | "30d";
const RANGES: Record<RangeKey, { buckets: number; daily: boolean; span: string; before: string }> = {
  "24h": { buckets: 24, daily: false, span: "last 24 hours", before: "24 hours before" },
  "7d": { buckets: 7, daily: true, span: "last 7 days", before: "7 days before" },
  "30d": { buckets: 30, daily: true, span: "last 30 days", before: "30 days before" },
};
const RANGE_KEYS = Object.keys(RANGES) as RangeKey[];

type Data = {
  range: RangeKey;
  // When the rollups were read; both periods are cut relative to it.
  at: number;
  nodes: Node[];
  hosts: Host[];
  certs: Certificate[];
  cs: CrowdSecStatus | null;
  // Both periods, hosts summed away so the row count does not grow with them.
  rollups: RollupRow[];
  // More matched than one response carries: the oldest buckets are missing.
  truncated: boolean;
  // The current period per host, buckets summed away.
  hostRows: RollupRow[];
  events: AnalyticsEvent[];
  notices: NoticeItem[];
};

function Overview() {
  const router = useRouter();
  const [range, setRange] = useState<RangeKey>("24h");
  const [data, setData] = useState<Data | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<AnalyticsEvent | null>(null);
  const loadSeq = useRef(0);

  async function load(r: RangeKey) {
    const mine = ++loadSeq.current;
    try {
      const { buckets, daily } = RANGES[r];
      const at = Date.now();
      const period = daily ? "daily" : "hourly";
      const start = windowStart(buckets, daily, at);
      // Twice the range, so the period before is there to compare with.
      const from = new Date(windowStart(2 * buckets, daily, at)).toISOString();
      const [nodes, hosts, certs, cs, hist, byHost, live, notices] = await Promise.all([
        api.nodes(),
        api.hosts(),
        api.certificates(),
        api.crowdsecStatus().catch(() => null),
        api.analyticsRollups(period, { from, group: "bucket" }),
        api.analyticsRollups(period, { from: new Date(start).toISOString(), group: "host" }),
        api.analyticsLive(200),
        api.notices().catch(() => [] as NoticeItem[]),
      ]);
      if (mine !== loadSeq.current) return; // a newer range won
      setData({
        range: r,
        at,
        nodes,
        hosts,
        certs,
        cs,
        rollups: hist.rows ?? [],
        truncated: !!hist.truncated,
        hostRows: byHost.rows ?? [],
        events: live.events ?? [],
        notices: notices ?? [],
      });
      setErr(null);
    } catch (e) {
      if (isUnauthorized(e) || mine !== loadSeq.current) return;
      setErr(e instanceof Error ? e.message : "Failed to load overview");
    }
  }

  useEffect(() => {
    load(range);
    const t = setInterval(() => load(range), POLL_MS);
    return () => clearInterval(t);
  }, [range]);

  const derived = useMemo(() => {
    if (!data) return null;
    const { buckets, daily } = RANGES[data.range];
    const span = buckets * (daily ? 864e5 : 36e5);
    const series = seriesFilled(data.rollups, buckets, daily, data.at);
    // A cut response is missing its oldest buckets, which is the period
    // before: no comparison is better than one against buckets read as zero.
    const before = data.truncated ? null : seriesFilled(data.rollups, buckets, daily, data.at - span);
    const oldest = data.rollups.reduce((t, r) => Math.min(t, new Date(r.bucket_start).getTime()), Infinity);
    const posture = computePosture({
      nodes: data.nodes,
      hosts: data.hosts,
      certs: data.certs,
      crowdsec: data.cs,
    });
    return {
      series,
      before,
      now: seriesTotals(series),
      // The current period's last bucket is still filling, so the period
      // before is counted up to the same point in its own last bucket.
      was: before ? seriesTotals(before, bucketElapsed(daily, data.at)) : null,
      // The cut reached into the current period itself.
      partial: data.truncated && oldest > (series[0].start ?? 0),
      busiest: hostStats(data.hostRows).slice(0, 5),
      posture,
      enabledHosts: data.hosts.filter((h) => h.enabled).length,
      nodes: data.nodes.filter((n) => !n.revoked),
      blockedEvents: data.events.filter((e) => e.block_stage),
    };
  }, [data]);

  const shown = data ? RANGES[data.range] : RANGES[range];

  return (
    <>
      <PageHeader
        title="Overview"
        description={`Every edge node over the ${shown.span}, compared with the ${shown.before}. Refreshes every 10 seconds.`}
        actions={
          <>
            <div role="group" aria-label="Time range" className="flex gap-0.5 rounded-[11px] border border-border bg-panel p-[3px]">
              {RANGE_KEYS.map((k) => (
                <button
                  key={k}
                  type="button"
                  aria-pressed={range === k}
                  onClick={() => setRange(k)}
                  className={`h-[30px] rounded-lg px-3 text-[13px] font-bold transition-colors ${
                    range === k ? "bg-accent text-ink" : "text-dim hover:text-fg"
                  }`}
                >
                  {k}
                </button>
              ))}
            </div>
            <Link href="/hosts?new=1" className="btn btn-primary">
              <Plus size={16} strokeWidth={2.4} aria-hidden /> Add host
            </Link>
          </>
        }
      />

      {err && (
        <div className="mt-6">
          <ErrorState message={err} onRetry={() => load(range)} />
        </div>
      )}

      {data && data.notices.length > 0 && (
        <div className="mt-6 space-y-2">
          {data.notices.map((n) => (
            <Notice key={`${n.kind}:${n.resource_id}`} tone="danger" title={n.title}>
              <p>{n.detail}</p>
              {n.next_attempt && <p className="mt-1 text-xs text-faint">Next attempt {fmtDateTime(n.next_attempt)}</p>}
            </Notice>
          ))}
        </div>
      )}

      {!derived || !data ? (
        <div className="card card-pad mt-6">
          <Loading rows={5} />
        </div>
      ) : (
        <div className="mt-6 flex flex-col gap-5">
          {derived.enabledHosts === 0 && <GettingStarted />}
          {derived.partial && (
            <Notice tone="warn" title="These figures cover only the most recent part of the range">
              <p>The range holds more data than one request returns. Pick a shorter range for complete figures.</p>
            </Notice>
          )}

          <Figures series={derived.series} now={derived.now} was={derived.was} before={shown.before} />

          <div className="grid gap-5 xl:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)]">
            <section className="card card-pad" aria-labelledby="traffic-h">
              <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
                <h2 id="traffic-h" className="section-title">
                  Traffic
                </h2>
                <ServedBlockedLegend previous={derived.was && derived.was.served + derived.was.blocked > 0 ? shown.before : undefined} />
                <Link href="/analytics" className="ml-auto text-sm font-semibold text-accent hover:text-fg">
                  Analytics
                </Link>
              </div>
              <div className="mt-5">
                <TimeSeriesChart
                  points={derived.series}
                  previous={derived.before ?? undefined}
                  height={230}
                  onSelect={(p) =>
                    p.start !== undefined &&
                    router.push(
                      requestsHref({ range: "custom", from: new Date(p.start).toISOString(), to: new Date(p.end ?? p.start + 3600_000).toISOString() }),
                    )
                  }
                />
              </div>
            </section>

            <Attention posture={derived.posture} />
          </div>

          <BusiestHosts rows={derived.busiest} hosts={data.hosts} span={shown.span} />

          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.7fr)]">
            <EdgeNodes nodes={derived.nodes} />

            <section className="card overflow-hidden" aria-labelledby="threats-h">
              <div className="flex items-center gap-2.5 px-6 pb-3 pt-5">
                <h2 id="threats-h" className="section-title">
                  Live threats
                </h2>
                <span className="rounded-full bg-ok/10 px-2 py-0.5 text-[11px] font-bold tracking-wide text-ok">LIVE</span>
                <Link href={requestsHref({ outcome: "blocked" })} className="ml-auto text-sm font-semibold text-accent hover:text-fg">
                  All blocked requests
                </Link>
              </div>
              {derived.blockedEvents.length === 0 ? (
                <p className="border-t border-border px-6 py-5 text-sm text-dim">Nothing blocked in the live window.</p>
              ) : (
                <ul>
                  {derived.blockedEvents.slice(0, 6).map((e, i) => (
                    <li key={e.id || `${e.timestamp_unix_ms}-${i}`} className="border-t border-border">
                      <button
                        type="button"
                        onClick={() => setOpen(e)}
                        aria-label={`Blocked request from ${e.client_ip || "unknown"} to ${e.domain || "unknown host"} at ${fmtTime(e.timestamp_unix_ms)}. Show details`}
                        className="grid w-full grid-cols-[4.5rem_minmax(0,1fr)_auto] items-center gap-3 px-6 py-2.5 text-left text-sm transition-colors hover:bg-panel-2/60 sm:grid-cols-[4.5rem_11rem_minmax(0,1fr)_auto]"
                      >
                        <span className="font-mono text-xs text-faint">{fmtTime(e.timestamp_unix_ms)}</span>
                        <span className="truncate font-mono text-xs">
                          {e.client_ip || "—"} {e.country && <span className="text-faint">{e.country}</span>}
                        </span>
                        <span className="hidden min-w-0 truncate text-dim sm:block">
                          <span className="text-fg">{outcomeOf(e).short}</span> · {e.domain || "—"} <span className="font-mono text-xs text-faint">{e.path}</span>
                        </span>
                        <span className="justify-self-end rounded-lg bg-danger/10 px-2.5 py-1 text-xs font-bold text-danger">Blocked</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </div>
      )}
      {open && <RequestDetail event={open} onClose={() => setOpen(null)} />}
    </>
  );
}

type Totals = ReturnType<typeof seriesTotals>;
type Points = ReturnType<typeof seriesFilled>;

function percent(part: number, whole: number): string {
  if (whole <= 0) return "—";
  const p = (part / whole) * 100;
  if (p > 0 && p < 0.05) return "<0.1%";
  return `${p.toFixed(1)}%`;
}

// "Up 12% on the 24 hours before". Says so when there is nothing to compare,
// and makes no claim when the period before could not be read (prev null).
function change(cur: number, prev: number | null, before: string): string {
  if (prev === null) return `No comparison with the ${before}`;
  if (prev <= 0) return cur > 0 ? `Nothing in the ${before}` : "No traffic yet";
  const p = ((cur - prev) / prev) * 100;
  const size = Math.abs(p);
  if (size < 0.5) return `Level with the ${before}`;
  return `${p > 0 ? "Up" : "Down"} ${size >= 10 ? Math.round(size) : size.toFixed(1)}% on the ${before}`;
}

// The five headline figures for the range, each with its trend across the
// range's buckets and a line comparing it with the period before.
function Figures({ series, now, was, before }: { series: Points; now: Totals; was: Totals | null; before: string }) {
  const total = now.served + now.blocked;
  const wasTotal = was ? was.served + was.blocked : 0;
  const [data, unit] = fmtDataParts(now.bytes);
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      <Figure
        label="Requests served"
        value={fmtCount(now.served)}
        sub={change(now.served, was ? was.served : null, before)}
        trend={series.map((p) => p.ok)}
      />
      <Figure
        label="Requests blocked"
        value={fmtCount(now.blocked)}
        sub={
          total > 0
            ? `${percent(now.blocked, total)} of traffic${was && wasTotal > 0 ? `, was ${percent(was.blocked, wasTotal)}` : ""}`
            : "No traffic yet"
        }
        trend={series.map((p) => p.blocked)}
        color="var(--danger)"
      />
      <Figure
        label="Response time"
        value={now.avgMs === null ? "—" : fmtLatency(now.avgMs)}
        unit={now.avgMs === null ? undefined : "average"}
        sub={!was || was.avgMs === null ? "Blocked requests are not counted" : `Was ${fmtLatency(was.avgMs)} in the ${before}`}
        trend={series.map((p) => (p.ok > 0 ? (p.latSum ?? 0) / p.ok : 0))}
      />
      <Figure
        label="Upstream errors"
        value={percent(now.errors, now.served)}
        sub={`${fmtInt(now.errors)} ${now.errors === 1 ? "response was" : "responses were"} 5xx${
          was && was.served > 0 ? `, rate was ${percent(was.errors, was.served)}` : ""
        }`}
        trend={series.map((p) => (p.ok > 0 ? (p.errors ?? 0) / p.ok : 0))}
      />
      <Figure label="Data sent" value={data} unit={unit} sub={change(now.bytes, was ? was.bytes : null, before)} trend={series.map((p) => p.bytes ?? 0)} />
    </div>
  );
}

function Figure({
  label,
  value,
  unit,
  sub,
  trend,
  color,
}: {
  label: string;
  value: string;
  unit?: string;
  sub: string;
  trend: number[];
  color?: string;
}) {
  return (
    <div className="card p-5">
      <div className="text-sm font-medium text-dim">{label}</div>
      <div className="display-num mt-2 text-3xl">
        {value}
        {unit && <span className="ml-1.5 font-sans text-sm font-medium tracking-normal text-dim">{unit}</span>}
      </div>
      <div className="mt-1.5 text-xs text-faint">{sub}</div>
      <div className="mt-3">
        <Sparkline values={trend} width={360} height={30} color={color} />
      </div>
    </div>
  );
}

// What needs the operator: posture checks that do not pass, each with what
// it concerns and where to fix it, then the ones that do pass.
function Attention({ posture }: { posture: Posture }) {
  const issues = posture.checks.filter((c) => c.state !== "pass");
  const passing = posture.checks.filter((c) => c.state === "pass");
  const failing = issues.some((c) => c.state === "fail");
  return (
    <section className="card card-pad" aria-labelledby="attention-h">
      <div className="flex items-center gap-2.5">
        <h2 id="attention-h" className="section-title">
          Needs attention
        </h2>
        {issues.length > 0 && (
          <span
            className={`inline-flex h-[22px] min-w-[22px] items-center justify-center rounded-full px-1.5 text-xs font-bold text-ink ${
              failing ? "bg-danger" : "bg-warn"
            }`}
          >
            {issues.length}
          </span>
        )}
        <span className="ml-auto text-sm text-dim">
          Posture <span className="font-mono text-fg">{posture.score}</span> / 100
        </span>
      </div>

      {issues.length === 0 ? (
        <p className="mt-4 text-sm text-dim">Nothing needs you right now.</p>
      ) : (
        <ul className="mt-4 flex flex-col gap-2.5">
          {issues.map((c) => (
            <li key={c.id} className="flex items-start gap-3 rounded-xl border border-border-strong px-3.5 py-3">
              <CheckIcon state={c.state} />
              <div className="min-w-0 flex-1 text-sm">
                <div className="font-semibold">{c.title}</div>
                <div className="mt-0.5 text-xs text-dim">{concerns(c)}</div>
              </div>
              <Link href={c.href} className="shrink-0 self-center text-sm font-bold text-accent hover:text-fg">
                {c.action}
              </Link>
            </li>
          ))}
        </ul>
      )}

      {passing.length > 0 && (
        <ul className="mt-4 flex flex-col gap-2.5 border-t border-border pt-4">
          {passing.map((c) => (
            <li key={c.id} className="flex items-start gap-2.5 text-sm text-dim">
              <CheckIcon state="pass" />
              <span>{c.title}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// The check's own detail, or the first few names it is about.
function concerns(c: PostureCheck): string {
  if (c.names.length === 0) return c.detail;
  const shown = c.names.slice(0, 3).join(", ");
  return c.names.length > 3 ? `${shown} and ${c.names.length - 3} more` : shown;
}

function CheckIcon({ state }: { state: CheckState }) {
  if (state === "pass") return <CheckCircle2 size={18} className="mt-px shrink-0 text-ok" aria-label="Passing" />;
  if (state === "warn") return <AlertTriangle size={18} className="mt-px shrink-0 text-warn" aria-label="Warning" />;
  return <XCircle size={18} className="mt-px shrink-0 text-danger" aria-label="Failing" />;
}

const KIND_LABEL: Record<string, string> = { redirect: "Redirect", dead: "404", stream: "Stream" };

// The layers a host has on. A proxy host without HTTPS or a WAF says so.
function layers(h: Host): { label: string; gap?: boolean }[] {
  if (h.kind && h.kind !== "proxy") return [{ label: KIND_LABEL[h.kind] ?? h.kind }];
  const out: { label: string; gap?: boolean }[] = [];
  out.push(h.tls_mode === "none" ? { label: "HTTP only", gap: true } : { label: "HTTPS" });
  out.push(h.waf_profile_id ? { label: "WAF" } : { label: "WAF off", gap: true });
  if (h.crowdsec_enabled) out.push({ label: "CrowdSec" });
  if ((h.geo_allow?.length ?? 0) + (h.geo_deny?.length ?? 0) > 0) out.push({ label: "GeoIP" });
  if (h.rate_limit_rps > 0) out.push({ label: "Rate limit" });
  if (h.access_list_id) out.push({ label: "Access list" });
  return out;
}

function BusiestHosts({ rows, hosts, span }: { rows: HostStats[]; hosts: Host[]; span: string }) {
  const byID = useMemo(() => new Map(hosts.map((h) => [h.id, h])), [hosts]);
  return (
    <section className="card card-pad" aria-labelledby="busiest-h">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 id="busiest-h" className="section-title">
          Busiest hosts
        </h2>
        <span className="text-xs text-faint">by requests, {span}</span>
        <Link href="/hosts" className="ml-auto text-sm font-semibold text-accent hover:text-fg">
          All {fmtInt(hosts.length)} {hosts.length === 1 ? "host" : "hosts"}
        </Link>
      </div>
      {rows.length === 0 ? (
        <p className="mt-4 text-sm text-dim">No traffic in the {span} yet.</p>
      ) : (
        <Table
          bare
          className="mt-2"
          columns={[
            { label: "Host" },
            { label: "Served", align: "right" },
            { label: "Blocked", align: "right" },
            { label: "5xx rate", align: "right" },
            { label: "Average", align: "right" },
            { label: "Protection" },
          ]}
        >
          {rows.map((r) => {
            const h = byID.get(r.hostID);
            return (
              <tr key={r.hostID} className="table-row">
                <td className="py-3 pr-5">
                  <Link
                    href={requestsHref({ host_id: r.hostID })}
                    className="block max-w-[18rem] truncate font-semibold hover:text-accent"
                    aria-label={`${r.domain || "Unknown host"}. Open its requests`}
                  >
                    {h?.domain_names[0] ?? r.domain ?? "—"}
                  </Link>
                </td>
                <td className="py-3 pr-5 text-right font-mono text-xs">{fmtCount(r.served)}</td>
                <td className="py-3 pr-5 text-right font-mono text-xs">{fmtCount(r.blocked)}</td>
                <td className="py-3 pr-5 text-right font-mono text-xs">{percent(r.errors, r.served)}</td>
                <td className="py-3 pr-5 text-right font-mono text-xs">{fmtLatency(r.avgMs)}</td>
                <td className="py-3">
                  {h ? (
                    <span className="flex flex-wrap gap-1.5">
                      {layers(h).map((l) => (
                        <span
                          key={l.label}
                          className={`whitespace-nowrap rounded-md px-2 py-0.5 text-[11px] font-bold ${
                            l.gap ? "bg-warn/10 text-warn" : "bg-panel-2 text-dim"
                          }`}
                        >
                          {l.label}
                        </span>
                      ))}
                    </span>
                  ) : (
                    <span className="text-xs text-faint">Host deleted</span>
                  )}
                </td>
              </tr>
            );
          })}
        </Table>
      )}
    </section>
  );
}

function EdgeNodes({ nodes }: { nodes: Node[] }) {
  return (
    <section className="card card-pad" aria-labelledby="nodes-h">
      <div className="flex items-baseline gap-3">
        <h2 id="nodes-h" className="section-title">
          Edge nodes
        </h2>
        <Link href="/nodes" className="ml-auto text-sm font-semibold text-accent hover:text-fg">
          Manage nodes
        </Link>
      </div>
      {nodes.length === 0 ? (
        <p className="mt-4 text-sm text-dim">No edge nodes enrolled. Enrol a proxy to serve traffic.</p>
      ) : (
        // Four short columns: narrower than the shared Table's minimum width.
        <div className="mt-2 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs font-semibold text-faint">
                <th scope="col" className="py-3 pr-4 font-semibold">
                  Node
                </th>
                <th scope="col" className="whitespace-nowrap py-3 pr-4 text-right font-semibold">
                  Requests/s
                </th>
                <th scope="col" className="py-3 pr-4 text-right font-semibold">
                  Median
                </th>
                <th scope="col" className="py-3 text-right font-semibold">
                  99th
                </th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => (
                <tr key={n.id} className="table-row">
                  <td className="py-3 pr-4">
                    <div className="font-semibold">
                      <StatusDot tone={n.online ? "ok" : "danger"}>{n.name}</StatusDot>
                    </div>
                    <div className="mt-0.5 pl-[14px] text-xs text-faint">
                      {n.online ? "Online" : "Offline"}
                      {n.agent_version ? `, ${n.agent_version}` : ""}
                    </div>
                  </td>
                  <td className="py-3 pr-4 text-right font-mono text-xs">{rate(n.rps)}</td>
                  <td className="whitespace-nowrap py-3 pr-4 text-right font-mono text-xs">{sampled(n, n.p50_ms)}</td>
                  <td className="whitespace-nowrap py-3 text-right font-mono text-xs">{sampled(n, n.p99_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

// A node's latency, or a dash when it served nothing in the live window:
// the API reports 0 then, which is no sample rather than a fast one.
function sampled(n: Node, ms?: number): string {
  return n.requests ? fmtLatency(ms) : "—";
}

function rate(rps?: number): string {
  if (rps === undefined || rps === null || Number.isNaN(rps)) return "—";
  return rps < 10 ? rps.toFixed(1) : fmtInt(rps);
}

// Nothing to protect yet: point at the first step instead of an empty page.
function GettingStarted() {
  return (
    <section aria-labelledby="start-h" className="card hero-glow grid items-center gap-8 p-6 sm:p-7 lg:grid-cols-[auto_minmax(0,1fr)]">
      <LogoMark size={112} className="opacity-90" />
      <div>
        <div className="kicker inline-flex items-center gap-2 text-accent">
          <span aria-hidden className="h-2 w-2 rounded-full bg-accent ring-[5px] ring-accent/20" />
          <span id="start-h">Getting started</span>
        </div>
        <p className="display-num mt-3 text-4xl leading-[1.05] sm:text-[2.6rem]">
          Add your first host
          <br />
          <span className="text-faint">to start protecting traffic</span>
        </p>
        <p className="mt-3 max-w-xl text-sm text-dim">
          Point a domain at an upstream. Aegis handles TLS, the WAF, CrowdSec and rate limits, and this page shows what each
          host serves and how well it is covered.
        </p>
        <Link href="/hosts?new=1" className="btn btn-primary mt-5">
          <Plus size={16} strokeWidth={2.4} aria-hidden /> Add host
        </Link>
      </div>
    </section>
  );
}
