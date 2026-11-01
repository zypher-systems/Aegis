"use client";

import { FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Ban, Globe2, Radio, ShieldCheck } from "lucide-react";
import { api, isUnauthorized } from "@/lib/api";
import type {
  AnalyticsEvent,
  AnalyticsSummary,
  CrowdSecAlert,
  CrowdSecDecision,
  CrowdSecStatus,
  GeoRollupRow,
  Host,
  RollupRow,
} from "@/lib/types";
import { AppShell } from "@/components/app-shell";
import { BarChart, ServedBlockedLegend, StageBars, StageDonut, TimeSeriesChart, type SeriesPoint } from "@/components/charts";
import { RequestDetail } from "@/components/request-detail";
import { RequestsExplorer } from "@/components/requests-explorer";
import { CountryMap, geoCounts } from "@/components/country-map";
import { countryName } from "@/lib/countries";
import { POLL_MS } from "@/lib/poll";
import {
  Dialog,
  Empty,
  ErrorState,
  Field,
  Loading,
  Notice,
  PageHeader,
  Pager,
  SearchInput,
  StatusPill,
  TabPanel,
  Table,
  Tabs,
  useHashTab,
  usePaged,
  type Tone,
} from "@/components/ui";
import { fmtCount, fmtInt, fmtMs, fmtTime } from "@/lib/format";
import { hourlySeriesFilled, rollupSeries, rollupStages, rollupTotals } from "@/lib/rollups";
import { filtersFromSearch, filtersToSearch, outcomeOf, statusTone, type RequestFilters, type RequestRange } from "@/lib/requests";

type RangeKey = "live" | "24h" | "7d" | "30d";
const TAB_IDS = ["traffic", "security", "requests", "crowdsec", "feed"] as const;
type TabId = (typeof TAB_IDS)[number];

export default function AnalyticsPage() {
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [events, setEvents] = useState<AnalyticsEvent[] | null>(null);
  const [rollups, setRollups] = useState<RollupRow[]>([]);
  const [geoRows, setGeoRows] = useState<GeoRollupRow[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [range, setRange] = useState<RangeKey>("live");
  const [hostID, setHostID] = useState("");
  const [cs, setCs] = useState<CrowdSecStatus | null>(null);
  const [decisions, setDecisions] = useState<CrowdSecDecision[]>([]);
  const [decTotal, setDecTotal] = useState(0);
  const [byOrigin, setByOrigin] = useState<Record<string, number>>({});
  const [decPage, setDecPage] = useState(1);
  const [decQuery, setDecQuery] = useState("");
  const [decQ, setDecQ] = useState("");
  const [decOrigin, setDecOrigin] = useState("");
  const [alerts, setAlerts] = useState<CrowdSecAlert[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [csErr, setCsErr] = useState<string | null>(null);
  const [banIP, setBanIP] = useState("");
  const [banDur, setBanDur] = useState("24h");
  const [banReason, setBanReason] = useState("");
  const [banBusy, setBanBusy] = useState(false);
  const [unbanBusy, setUnbanBusy] = useState<number | null>(null);
  const [banMsg, setBanMsg] = useState<string | null>(null);
  const [geoReady, setGeoReady] = useState<boolean | null>(null);
  const [tab, setTab] = useHashTab<TabId>(TAB_IDS, "traffic");
  // Requests explorer filters; the host lives in hostID (the header select).
  const [reqFilters, setReqFilters] = useState<RequestFilters>({ range: "24h" });
  const [openEvent, setOpenEvent] = useState<AnalyticsEvent | null>(null);
  const [openDecision, setOpenDecision] = useState<CrowdSecDecision | null>(null);

  // /analytics?country=RU#requests (links from the Overview and request
  // details) opens the explorer with those filters.
  useEffect(() => {
    const f = filtersFromSearch(window.location.search);
    if (f.host_id) setHostID(f.host_id);
    const { host_id: _h, ...rest } = f;
    setReqFilters(rest);
  }, []);

  // Keep the explorer's filters in the URL so the view can be shared.
  useEffect(() => {
    if (tab !== "requests") return;
    const qs = filtersToSearch({ ...reqFilters, host_id: hostID || undefined });
    history.replaceState(null, "", `/analytics${qs ? `?${qs}` : ""}#requests`);
  }, [tab, reqFilters, hostID]);

  function showRequests(f: RequestFilters) {
    const { host_id, ...rest } = f;
    setHostID(host_id ?? "");
    setReqFilters(rest);
    setTab("requests");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  // From a chart, list or map: these filters over the page's time range.
  function drill(f: Partial<RequestFilters>) {
    showRequests({ range: explorerRange(range), host_id: hostID || undefined, ...f });
  }
  function drillBucket(p: SeriesPoint) {
    if (p.start === undefined || p.end === undefined) return;
    showRequests({
      range: "custom",
      from: new Date(p.start).toISOString(),
      to: new Date(p.end).toISOString(),
      host_id: hostID || undefined,
    });
  }

  const loadSeq = useRef(0);
  async function load(nextRange = range, host = hostID) {
    const mine = ++loadSeq.current;
    try {
      const args = rollupArgs(nextRange, host);
      const [sum, live, hist, geoHist, status, hostList, geo] = await Promise.all([
        api.analyticsSummary(),
        api.analyticsLive(40),
        api.analyticsRollups(args.period, args.opts),
        api.analyticsGeo(args.period, args.opts).catch(() => ({ rows: [] as GeoRollupRow[] })),
        api.crowdsecStatus(),
        api.hosts(),
        api.geoipStatus(),
      ]);
      if (mine !== loadSeq.current) return; // a newer range/host won
      setSummary(sum);
      setEvents(live.events ?? []);
      setRollups(hist.rows ?? []);
      setGeoRows(geoHist.rows ?? []);
      setHosts(hostList ?? []);
      setCs(status);
      setGeoReady(!!(geo.ready ?? geo.configured));
      setErr(null);
      try {
        const a = await api.crowdsecAlerts();
        setAlerts(a.alerts ?? []);
      } catch {
        setAlerts([]);
      }
    } catch (e) {
      if (isUnauthorized(e)) return;
      setErr(e instanceof Error ? e.message : "Failed to load analytics");
    }
  }

  useEffect(() => {
    load(range, hostID);
    const t = setInterval(() => load(range, hostID), POLL_MS);
    return () => clearInterval(t);
  }, [range, hostID]);

  // Decisions are paged, searched and filtered on the server; the API caches
  // the LAPI list for 10s, so polling here costs one LAPI call per window.
  async function loadDecisions(page = decPage, q = decQ, origin = decOrigin) {
    try {
      const d = await api.crowdsecDecisions({ limit: DEC_PAGE, offset: (page - 1) * DEC_PAGE, q, origin });
      setDecisions(d.decisions ?? []);
      setDecTotal(d.total ?? 0);
      setByOrigin(d.by_origin ?? {});
      setCsErr(null);
    } catch (e2) {
      if (isUnauthorized(e2)) return;
      setDecisions([]);
      setDecTotal(0);
      setCsErr(e2 instanceof Error ? e2.message : "CrowdSec decisions unavailable");
    }
  }

  useEffect(() => {
    loadDecisions(decPage, decQ, decOrigin);
    const t = setInterval(() => loadDecisions(decPage, decQ, decOrigin), POLL_MS);
    return () => clearInterval(t);
  }, [decPage, decQ, decOrigin]);

  // Debounce the search box; a new search or origin starts at page 1.
  useEffect(() => {
    const t = setTimeout(() => {
      setDecQ(decQuery.trim());
      setDecPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [decQuery]);

  const decPages = Math.max(1, Math.ceil(decTotal / DEC_PAGE));
  const decAll = Object.values(byOrigin).reduce((a, b) => a + b, 0);

  const live = range === "live";
  const daily = range === "7d" || range === "30d";
  const histTotals = rollupTotals(rollups);
  const histStages = rollupStages(rollups);
  const stageRows = live ? (summary?.blocked_by_stage ?? []) : histStages;
  const windowN = live ? (summary?.window_events ?? 0) : histTotals.total;
  const blocked = live ? (summary?.blocked ?? 0) : histTotals.blocked;
  const shownEvents = useMemo(() => (events ?? []).filter((e) => !hostID || e.host_id === hostID), [events, hostID]);
  const blockedEvents = useMemo(() => shownEvents.filter((e) => e.block_stage), [shownEvents]);
  const mapData = live ? geoCounts(summary?.geo ?? []) : geoCounts(geoRows);
  const feedPages = usePaged(shownEvents, 50);
  const ruleHits = useMemo(() => countBy(shownEvents.filter((e) => e.waf_rule_id), (e) => e.waf_rule_id || ""), [shownEvents]);
  const blockedClients = useMemo(() => countBy(blockedEvents, (e) => e.client_ip || ""), [blockedEvents]);
  const rangeLabel = live ? "live window" : `last ${range}`;

  async function onBan(e: FormEvent) {
    e.preventDefault();
    setBanBusy(true);
    setBanMsg(null);
    setErr(null);
    try {
      const out = await api.crowdsecBan({
        ip: banIP.trim(),
        duration: banDur,
        reason: banReason.trim() || undefined,
      });
      setBanIP("");
      setBanReason("");
      setBanMsg(out.warning || `Banned ${out.value} for ${out.duration}.`);
      await loadDecisions();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Ban failed");
    } finally {
      setBanBusy(false);
    }
  }

  async function onUnban(id: number) {
    setUnbanBusy(id);
    setErr(null);
    try {
      await api.crowdsecUnban(id);
      await loadDecisions();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Unban failed");
    } finally {
      setUnbanBusy(null);
    }
  }

  return (
    <AppShell>
      <PageHeader
        title="Analytics"
        description="Live reads the in-memory window; 24h, 7d and 30d read persisted rollups. Refreshes every 10 seconds."
        actions={
          <>
            {tab !== "requests" && (
            <div role="group" aria-label="Time range" className="flex gap-0.5 rounded-[11px] border border-border bg-panel p-[3px]">
              {(["live", "24h", "7d", "30d"] as const).map((k) => (
                <button
                  key={k}
                  type="button"
                  aria-pressed={range === k}
                  onClick={() => setRange(k)}
                  className={`h-[30px] rounded-lg px-3 text-[13px] font-bold transition-colors ${
                    range === k ? "bg-accent text-ink" : "text-dim hover:text-fg"
                  }`}
                >
                  {k === "live" ? "Live" : k}
                </button>
              ))}
            </div>
            )}
            <select aria-label="Host" className="input w-56 text-sm" value={hostID} onChange={(e) => setHostID(e.target.value)}>
              <option value="">All hosts</option>
              {hosts.map((h) => (
                <option key={h.id} value={h.id}>
                  {(h.domain_names ?? [])[0] || h.id.slice(0, 8)}
                </option>
              ))}
            </select>
          </>
        }
      />

      {err && (
        <div className="mt-5">
          <ErrorState message={err} onRetry={() => load(range, hostID)} />
        </div>
      )}
      {geoReady === false && (
        <div className="mt-5">
          <Notice tone="warn" title="GeoIP database missing">
            Country allow/deny fails closed (403) and the map stays empty until an MMDB is loaded.
          </Notice>
        </div>
      )}

      <div className="mt-6">
        <Tabs
          label="Analytics sections"
          value={tab}
          onChange={setTab}
          items={[
            { id: "traffic", label: "Traffic" },
            { id: "security", label: "Security", count: blocked },
            { id: "requests", label: "Requests" },
            { id: "crowdsec", label: "CrowdSec", count: decAll },
            { id: "feed", label: "Live feed" },
          ]}
        />
      </div>

      <div className="mt-6">
        <TabPanel id="traffic" active={tab === "traffic"}>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatCard label="Received" value={summary ? fmtCount(summary.received ?? 0) : "…"} sub="since the API started" />
            <StatCard label={live ? "In window" : "In range"} value={fmtCount(windowN)} sub={rangeLabel} />
            <StatCard
              label="Blocked"
              value={fmtCount(blocked)}
              sub={windowN > 0 ? `${((blocked / windowN) * 100).toFixed(1)}% of requests` : rangeLabel}
              tone={blocked > 0 ? "text-danger" : ""}
            />
            <StatCard
              label="Latency p50"
              value={live && summary ? fmtMs(Number(summary.p50_ms ?? 0)) : "—"}
              sub={live && summary ? `p99 ${fmtMs(Number(summary.p99_ms ?? 0))}` : "Live window only"}
            />
          </div>

          <Card className="mt-5" title={`${daily ? "Daily" : "Hourly"} traffic`} aside={<ServedBlockedLegend />}>
            <div className="mt-5">
              <TimeSeriesChart
                points={daily ? rollupSeries(rollups, true) : hourlySeriesFilled(rollups)}
                height={220}
                onSelect={drillBucket}
              />
            </div>
          </Card>

          <div className="mt-5 grid gap-5 lg:grid-cols-2">
            <Card title="Latency histogram" description="Live window, milliseconds">
              {!live ? (
                <p className="mt-4 text-sm text-dim">Switch to Live for the histogram. Buckets are not kept in rollups.</p>
              ) : !summary || (summary.histogram ?? []).every((b) => b.count === 0) ? (
                <p className="mt-4 text-sm text-dim">No samples yet. Proxy a request to see buckets.</p>
              ) : (
                <BarChart rows={(summary.histogram ?? []).map((b) => ({ label: b.le === 0 ? "+Inf" : `≤ ${b.le}`, count: b.count }))} />
              )}
            </Card>
            <Card
              title="Countries"
              icon={<Globe2 size={17} aria-hidden />}
              description={live ? "Live window, country at ingest" : "Persisted country rollups for this range"}
            >
              <div className="mt-4">
                <CountryMap counts={mapData} missingMMDB={geoReady === false} onSelect={(iso) => drill({ country: iso })} />
              </div>
              {geoReady !== false && Object.keys(mapData).length > 0 && (
                <RankList
                  rows={Object.entries(mapData)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 6)
                    .map(([iso, n]) => ({ key: iso, label: countryName(iso), count: n }))}
                  tag
                  onSelect={(iso) => drill({ country: iso })}
                  noun="country"
                />
              )}
            </Card>
          </div>

          <div className="mt-5 grid gap-5 lg:grid-cols-2">
            <Card title="Top paths" description="Live window">
              {live && summary?.top_paths?.length ? (
                <RankList
                  rows={summary.top_paths.map((r) => ({ key: r.key, label: r.key || "/", count: r.count }))}
                  mono
                  onSelect={(path) => drill({ path: path || "/" })}
                  noun="path"
                />
              ) : (
                <p className="mt-4 text-sm text-dim">{live ? "No paths yet." : "Live window only."}</p>
              )}
            </Card>
            <Card title="Top clients" description="Live window">
              {live && summary?.top_clients?.length ? (
                <RankList
                  rows={summary.top_clients.map((r) => ({ key: r.key, label: r.key || "—", count: r.count }))}
                  mono
                  onSelect={(ip) => drill({ ip })}
                  noun="client"
                />
              ) : (
                <p className="mt-4 text-sm text-dim">{live ? "No clients yet." : "Live window only."}</p>
              )}
            </Card>
          </div>
          {rollups.length > 0 && (
            <p className="mt-4 text-xs text-faint">
              {fmtInt(rollups.length)} rollup row{rollups.length === 1 ? "" : "s"} persisted.
            </p>
          )}
        </TabPanel>

        <TabPanel id="security" active={tab === "security"}>
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
            <Card title="Where attacks stop" icon={<ShieldCheck size={17} aria-hidden />} description={`Blocked requests by layer, ${rangeLabel}`}>
              <StageDonut rows={stageRows} empty="Nothing blocked in this range." onSelect={(stage) => drill({ stage })} />
            </Card>
            <Card title="By stage" description="Only requests a stage stopped are counted">
              <StageBars rows={stageRows} empty="No blocks in this range." onSelect={(stage) => drill({ stage })} />
            </Card>
          </div>
          <div className="mt-5 grid gap-5 lg:grid-cols-2">
            <Card title="WAF rule hits" description="OWASP CRS rule ids in the live window">
              {ruleHits.length === 0 ? (
                <p className="mt-4 text-sm text-dim">No WAF rules matched in the live window.</p>
              ) : (
                <RankList
                  rows={ruleHits.slice(0, 8).map((r) => ({ key: r.key, label: r.key, count: r.count }))}
                  mono
                  onSelect={(rule) => drill({ rule })}
                  noun="rule"
                />
              )}
            </Card>
            <Card title="Top blocked clients" description="Live window">
              {blockedClients.length === 0 ? (
                <p className="mt-4 text-sm text-dim">No blocked clients in the live window.</p>
              ) : (
                <RankList
                  rows={blockedClients.slice(0, 8).map((r) => ({ key: r.key, label: r.key, count: r.count }))}
                  mono
                  danger
                  onSelect={(ip) => drill({ ip, outcome: "blocked" })}
                  noun="client"
                />
              )}
            </Card>
          </div>
        </TabPanel>

        <TabPanel id="requests" active={tab === "requests"}>
          <RequestsExplorer filters={{ ...reqFilters, host_id: hostID || undefined }} onChange={showRequests} hosts={hosts} />
        </TabPanel>

        <TabPanel id="crowdsec" active={tab === "crowdsec"}>
          <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <Card title="Status" icon={<Radio size={17} aria-hidden />}>
              {cs === null ? (
                <Loading rows={2} />
              ) : !cs.configured ? (
                <p className="mt-4 text-sm text-dim">LAPI key not seeded yet. Check compose CROWDSEC_BOUNCER_KEY.</p>
              ) : (
                <dl className="mt-4 space-y-3 text-sm">
                  <Row label="Local API">
                    <StatusPill tone={cs.lapi_ok ? "ok" : "danger"}>{cs.lapi_ok ? "Reachable" : "Unreachable"}</StatusPill>
                  </Row>
                  <Row label="Host firewall">
                    <StatusPill tone={cs.firewall_enabled ? "ok" : "neutral"}>{cs.firewall_enabled ? "On" : "Off"}</StatusPill>
                  </Row>
                  <Row label="Manual bans">
                    <StatusPill tone={cs.can_ban ? "ok" : "warn"}>{cs.can_ban ? "Enabled" : "Not configured"}</StatusPill>
                  </Row>
                  <Row label="Endpoint">
                    <span className="block truncate font-mono text-xs text-dim">{cs.url || "—"}</span>
                  </Row>
                </dl>
              )}
            </Card>
            <Card title="Ban an IP on the firewall" icon={<Ban size={17} aria-hidden />}>
              <form className="mt-4 grid gap-3 sm:grid-cols-[minmax(0,1.3fr)_9rem_minmax(0,1fr)_auto] sm:items-end" onSubmit={onBan}>
                <Field label="IP or CIDR">
                  <input className="input font-mono" placeholder="203.0.113.9" value={banIP} onChange={(e) => setBanIP(e.target.value)} required />
                </Field>
                <Field label="Duration">
                  <select className="input" value={banDur} onChange={(e) => setBanDur(e.target.value)}>
                    <option value="4h">4 hours</option>
                    <option value="24h">24 hours</option>
                    <option value="7d">7 days</option>
                    <option value="30d">30 days</option>
                  </select>
                </Field>
                <Field label="Reason (optional)">
                  <input className="input" placeholder="scanner" value={banReason} onChange={(e) => setBanReason(e.target.value)} />
                </Field>
                <button type="submit" className="btn btn-primary h-10" disabled={banBusy || !cs?.can_ban}>
                  {banBusy ? "Banning…" : "Ban on firewall"}
                </button>
              </form>
              <p className="mt-3 text-xs text-faint">
                Manual bans are origin <span className="mono">cscli</span> and hit nftables, not L7. Private and loopback addresses are refused.
                {!cs?.can_ban ? " Set CROWDSEC_MACHINE_PASSWORD and restart crowdsec-init / API to enable bans." : ""}
              </p>
              {banMsg && <p className="mt-2 text-sm text-ok">{banMsg}</p>}
            </Card>
          </div>
          {csErr && cs?.configured && (
            <div className="mt-5">
              <Notice tone="danger" title="Could not load decisions and alerts">
                {csErr}
              </Notice>
            </div>
          )}
          <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
            <div className="min-w-0">
              <div className="mb-3 flex flex-wrap items-center gap-2.5">
                <h2 className="section-title mr-auto">Active decisions</h2>
                <div className="w-full sm:w-56">
                  <SearchInput value={decQuery} onChange={setDecQuery} placeholder="IP, scenario or origin" label="Search decisions" />
                </div>
              </div>
              {decAll > 0 && (
                <div role="group" aria-label="Filter by origin" className="mb-3 flex flex-wrap gap-2">
                  {[["", decAll] as const, ...Object.entries(byOrigin).sort((a, b) => b[1] - a[1])].map(([o, n]) => {
                    const on = decOrigin === o;
                    return (
                      <button
                        key={o || "all"}
                        type="button"
                        aria-pressed={on}
                        onClick={() => {
                          setDecOrigin(o);
                          setDecPage(1);
                        }}
                        className={`h-8 rounded-full px-3 text-xs font-bold transition-colors ${
                          on ? "bg-accent text-ink" : "border border-border-strong text-dim hover:text-fg"
                        }`}
                      >
                        {o || "All"} <span className={on ? "" : "text-faint"}>{fmtInt(n)}</span>
                      </button>
                    );
                  })}
                </div>
              )}
              {decisions.length === 0 ? (
                <Empty
                  body={
                    decQ || decOrigin
                      ? "No decisions match that search."
                      : "No active bans. CAPI community lists fill in after the engine has enrolled."
                  }
                />
              ) : (
                <>
                  <Table
                    columns={[
                      { label: "Value" },
                      { label: "Origin" },
                      { label: "Scenario" },
                      { label: <span className="sr-only">Actions</span>, align: "right" },
                    ]}
                  >
                    {decisions.map((d) => (
                      <tr key={`${d.id}-${d.value}`} className="table-row cursor-pointer" onClick={() => setOpenDecision(d)}>
                        <td className="py-2.5 pr-5 font-mono text-[13px]">
                          <button
                            type="button"
                            className="hover:text-accent"
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setOpenDecision(d);
                            }}
                          >
                            {d.value}
                          </button>
                        </td>
                        <td className="py-2.5 pr-5">
                          <span className="rounded-md border border-border-strong bg-panel-2 px-1.5 py-0.5 font-mono text-[11px] text-dim">
                            {d.origin || "—"}
                          </span>
                        </td>
                        <td className="py-2.5 pr-5 text-dim">{d.scenario || "—"}</td>
                        <td className="py-2.5 text-right">
                          {d.origin === "cscli" && d.id ? (
                            <button
                              type="button"
                              className="btn btn-danger"
                              disabled={unbanBusy === d.id || !cs?.can_ban}
                              onClick={(ev) => {
                                ev.stopPropagation();
                                onUnban(d.id);
                              }}
                            >
                              {unbanBusy === d.id ? "…" : "Unban"}
                            </button>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </Table>
                  <Pager page={decPage} pages={decPages} setPage={setDecPage} total={decTotal} pageSize={DEC_PAGE} noun="decisions" />
                </>
              )}
            </div>
            <div className="min-w-0">
              <h2 className="section-title mb-3">Recent L7 blocks</h2>
              {alerts.length === 0 ? (
                <Empty body="Turn CrowdSec on for a host and wait for a listed IP." />
              ) : (
                <Table columns={[{ label: "Time" }, { label: "Client" }, { label: "Origin" }]}>
                  {alerts.slice(0, 20).map((a, i) => (
                    <tr
                      key={`${a.timestamp_unix_ms}-${i}`}
                      className="table-row cursor-pointer"
                      onClick={() => a.client_ip && drill({ ip: a.client_ip, stage: "crowdsec" })}
                    >
                      <td className="py-2.5 pr-5 font-mono text-xs text-faint">{fmtTime(a.timestamp_unix_ms || null)}</td>
                      <td className="py-2.5 pr-5 font-mono text-[13px]">
                        {a.client_ip ? (
                          <button
                            type="button"
                            className="hover:text-accent"
                            aria-label={`Requests from ${a.client_ip} blocked by CrowdSec`}
                            onClick={(ev) => {
                              ev.stopPropagation();
                              drill({ ip: a.client_ip, stage: "crowdsec" });
                            }}
                          >
                            {a.client_ip}
                          </button>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="py-2.5 font-mono text-xs text-dim">{a.origin || "—"}</td>
                    </tr>
                  ))}
                </Table>
              )}
            </div>
          </div>
        </TabPanel>

        <TabPanel id="feed" active={tab === "feed"}>
          <div className="mb-3 flex flex-wrap items-center gap-2.5">
            <h2 className="section-title">Live request feed</h2>
            <span className="rounded-full bg-ok/10 px-2 py-0.5 text-[11px] font-bold tracking-wide text-ok">LIVE</span>
            <span className="text-xs text-faint">Newest first, from the in-memory window. Click a request for its details.</span>
          </div>
          {events === null ? (
            !err && (
              <div className="card card-pad">
                <Loading rows={5} label="Loading feed" />
              </div>
            )
          ) : shownEvents.length === 0 ? (
            <Empty body="The feed fills as the proxy emits telemetry." />
          ) : (
            <>
              <Table
                columns={[
                  { label: "Time" },
                  { label: "Status" },
                  { label: "Why" },
                  { label: "Host" },
                  { label: "Request" },
                  { label: "ms", align: "right" },
                  { label: "Client" },
                  { label: "Country" },
                ]}
              >
                {feedPages.pageItems.map((e, i) => {
                  const o = outcomeOf(e);
                  return (
                  <tr key={e.id || `${e.timestamp_unix_ms}-${i}`} className="table-row cursor-pointer" onClick={() => setOpenEvent(e)}>
                    <td className="py-2.5 pr-5 font-mono text-xs text-faint">{fmtTime(e.timestamp_unix_ms || null)}</td>
                    <td className="py-2.5 pr-5">
                      <StatusPill tone={statusTone(e.status)}>{e.status || "—"}</StatusPill>
                    </td>
                    <td className="py-2.5 pr-5 text-xs">
                      <span className={o.tone === "danger" ? "font-semibold text-danger" : o.tone === "warn" ? "font-semibold text-warn" : "text-faint"}>
                        {o.short}
                      </span>
                    </td>
                    <td className="py-2.5 pr-5">{e.domain || "—"}</td>
                    <td className="max-w-[18rem] py-2.5 pr-5">
                      <button
                        type="button"
                        className="block max-w-full truncate text-left font-mono text-xs text-dim hover:text-fg"
                        aria-label={`Details for ${e.method} ${e.path} at ${fmtTime(e.timestamp_unix_ms)}`}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          setOpenEvent(e);
                        }}
                      >
                        <span className="text-faint">{e.method}</span> {e.path || "/"}
                      </button>
                    </td>
                    <td className="py-2.5 pr-5 text-right font-mono text-xs">{e.duration_ms?.toFixed(2)}</td>
                    <td className="py-2.5 pr-5 font-mono text-xs text-dim">{e.client_ip || "—"}</td>
                    <td className="py-2.5 font-mono text-xs">{e.country || "—"}</td>
                  </tr>
                  );
                })}
              </Table>
              <Pager {...feedPages} noun="events" />
            </>
          )}
        </TabPanel>
      </div>

      {openEvent && (
        <RequestDetail
          event={openEvent}
          onClose={() => setOpenEvent(null)}
          onFilter={(f) => showRequests({ range: "24h", ...f })}
        />
      )}
      {openDecision && (
        <DecisionDetail
          d={openDecision}
          canUnban={!!cs?.can_ban}
          busy={unbanBusy === openDecision.id}
          onUnban={async () => {
            await onUnban(openDecision.id);
            setOpenDecision(null);
          }}
          onRequests={() => {
            drill({ ip: openDecision.value });
            setOpenDecision(null);
          }}
          onClose={() => setOpenDecision(null)}
        />
      )}
    </AppShell>
  );
}

// Live maps onto the explorer's shortest range; the others match.
function explorerRange(r: RangeKey): RequestRange {
  return r === "live" ? "1h" : r;
}

function DecisionDetail({
  d,
  canUnban,
  busy,
  onUnban,
  onRequests,
  onClose,
}: {
  d: CrowdSecDecision;
  canUnban: boolean;
  busy: boolean;
  onUnban: () => void;
  onRequests: () => void;
  onClose: () => void;
}) {
  const isIP = (d.scope || "").toLowerCase() === "ip";
  const manual = d.origin === "cscli";
  return (
    <Dialog
      title={<span className="font-mono">{d.value}</span>}
      description={`CrowdSec ${d.type || "ban"} decision`}
      onClose={onClose}
      footer={
        <>
          {manual && d.id ? (
            <button type="button" className="btn btn-danger mr-auto" disabled={busy || !canUnban} onClick={onUnban}>
              {busy ? "Unbanning…" : "Unban"}
            </button>
          ) : null}
          <button type="button" className="btn btn-primary" onClick={onClose}>
            Close
          </button>
        </>
      }
    >
      <dl className="space-y-2.5 text-sm">
        <DetailRow label="Value">
          <span className="font-mono">{d.value}</span>
        </DetailRow>
        <DetailRow label="Scope">{d.scope || "—"}</DetailRow>
        <DetailRow label="Action">{d.type || "—"}</DetailRow>
        <DetailRow label="Origin">
          <span className="rounded-md border border-border-strong bg-panel-2 px-1.5 py-0.5 font-mono text-[11px] text-dim">{d.origin || "—"}</span>{" "}
          <span className="text-faint">{originHelp(d.origin)}</span>
        </DetailRow>
        <DetailRow label="Scenario">
          <span className="break-all">{d.scenario || "—"}</span>
        </DetailRow>
        <DetailRow label="Expires in">{d.duration || "—"}</DetailRow>
        <DetailRow label="Decision ID">
          <span className="font-mono">{d.id || "—"}</span>
        </DetailRow>
      </dl>
      <p className="mt-4 text-xs text-faint">
        The L7 bouncer refuses this {isIP ? "address" : "range"} on every host with CrowdSec on; with the host firewall on,
        the firewall drops it too.
      </p>
      {isIP && (
        <button type="button" className="btn btn-secondary btn-sm mt-4" onClick={onRequests}>
          Requests from this IP
        </button>
      )}
    </Dialog>
  );
}

function originHelp(origin: string) {
  switch (origin) {
    case "CAPI":
      return "CrowdSec community blocklist";
    case "lists":
      return "a subscribed blocklist";
    case "cscli":
      return "a manual ban (dashboard or cscli)";
    case "crowdsec":
      return "this install's own detection";
    default:
      return "";
  }
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[7rem_minmax(0,1fr)] gap-3">
      <dt className="text-dim">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

function Card({
  title,
  description,
  icon,
  aside,
  className = "",
  children,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  aside?: ReactNode;
  className?: string;
  children?: ReactNode;
}) {
  return (
    <section className={`card card-pad min-w-0 ${className}`}>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <h2 className="section-title flex items-center gap-2">
          {icon && <span className="text-faint">{icon}</span>}
          {title}
        </h2>
        {aside}
      </div>
      {description && <p className="mt-1 text-xs text-faint">{description}</p>}
      {children}
    </section>
  );
}

function StatCard({ label, value, sub, tone = "" }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <div className="card p-5">
      <div className="text-sm font-medium text-dim">{label}</div>
      <div className={`display-num mt-2 text-3xl ${tone}`}>{value}</div>
      {sub && <div className="mt-1.5 text-xs text-faint">{sub}</div>}
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <dt className="shrink-0 text-dim">{label}</dt>
      <dd className="min-w-0 text-right">{children}</dd>
    </div>
  );
}

// Ranked list with proportional bars; the count is always printed.
// onSelect makes each row open its requests.
function RankList({
  rows,
  mono,
  tag,
  danger,
  onSelect,
  noun = "item",
}: {
  rows: { key: string; label: string; count: number }[];
  mono?: boolean;
  tag?: boolean;
  danger?: boolean;
  onSelect?: (key: string) => void;
  noun?: string;
}) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  return (
    <ul className="mt-3 space-y-0.5">
      {rows.map((r) => {
        const body = (
          <>
            <div className="flex items-center gap-2.5 text-sm">
              {tag && <span className="rounded-md border border-border-strong bg-panel-2 px-1.5 font-mono text-[11px] text-dim">{r.key}</span>}
              <span className={`truncate ${mono ? "font-mono text-[13px]" : ""}`}>{r.label}</span>
              <span className="ml-auto font-mono text-xs text-dim">{fmtInt(r.count)}</span>
            </div>
            <div className="mt-1.5 h-1 rounded-full bg-panel-2">
              <div className={`h-1 rounded-full ${danger ? "bg-danger" : "bg-accent"}`} style={{ width: `${Math.max(3, (r.count / max) * 100)}%` }} />
            </div>
          </>
        );
        return (
          <li key={r.key}>
            {onSelect ? (
              <button
                type="button"
                className="block w-full rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-panel-2"
                onClick={() => onSelect(r.key)}
                aria-label={`${r.label}: ${fmtInt(r.count)}. Open this ${noun}'s requests`}
              >
                {body}
              </button>
            ) : (
              <div className="px-2 py-1.5">{body}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function countBy<T>(items: T[], key: (t: T) => string) {
  const by: Record<string, number> = {};
  for (const it of items) {
    const k = key(it);
    if (k) by[k] = (by[k] || 0) + 1;
  }
  return Object.entries(by)
    .map(([k, count]) => ({ key: k, count }))
    .sort((a, b) => b.count - a.count);
}

function rollupArgs(range: RangeKey, hostID: string) {
  const now = Date.now();
  const iso = (ms: number) => new Date(ms).toISOString();
  const hid = hostID || undefined;
  if (range === "7d") {
    return { period: "daily" as const, opts: { from: iso(now - 7 * 864e5), host_id: hid } };
  }
  if (range === "30d") {
    return { period: "daily" as const, opts: { from: iso(now - 30 * 864e5), host_id: hid } };
  }
  return { period: "hourly" as const, opts: { from: iso(now - 864e5), host_id: hid } };
}

const DEC_PAGE = 25;
