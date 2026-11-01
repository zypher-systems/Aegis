"use client";

import { useEffect, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, RefreshCw, X } from "lucide-react";
import { api, isUnauthorized } from "@/lib/api";
import type { AnalyticsEvent, Host, RequestLogPage } from "@/lib/types";
import { Empty, ErrorState, Loading, Notice, SearchInput, StatusPill, Table } from "@/components/ui";
import { RequestDetail } from "@/components/request-detail";
import { COUNTRIES, countryName } from "@/lib/countries";
import { fmtDate, fmtInt, fmtTime } from "@/lib/format";
import { stageLabel } from "@/lib/rollups";
import { POLL_MS } from "@/lib/poll";
import { apiParams, outcomeOf, statusTone, type RequestFilters, type RequestRange } from "@/lib/requests";

const PAGE = 50;
const STAGES = ["waf", "crowdsec", "ratelimit", "geo", "acl"];
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

// The request log: every proxied request (or only blocked and flagged ones,
// per AEGIS_REQUEST_LOG), filtered on the server and paged newest first.
// Rows open the full request details.
export function RequestsExplorer({
  filters,
  onChange,
  hosts,
}: {
  filters: RequestFilters;
  onChange: (f: RequestFilters) => void;
  hosts: Host[];
}) {
  const [page, setPage] = useState<RequestLogPage | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Cursors of the pages before the current one; empty on the newest page.
  const [trail, setTrail] = useState<string[]>([]);
  const [cursor, setCursor] = useState("");
  const [open, setOpen] = useState<AnalyticsEvent | null>(null);
  const [search, setSearch] = useState(filters.q ?? "");
  const [ipDraft, setIpDraft] = useState(filters.ip ?? "");
  const seq = useRef(0);

  const key = JSON.stringify(filters);

  async function load(at = cursor) {
    const mine = ++seq.current;
    setBusy(true);
    try {
      const p = await api.analyticsRequests({ ...apiParams(filters), cursor: at || undefined, limit: PAGE });
      if (mine !== seq.current) return;
      setPage(p);
      setErr(null);
    } catch (e) {
      if (isUnauthorized(e) || mine !== seq.current) return;
      setErr(e instanceof Error ? e.message : "Failed to load requests");
    } finally {
      if (mine === seq.current) setBusy(false);
    }
  }

  // New filters start again at the newest page.
  useEffect(() => {
    setTrail([]);
    setCursor("");
    setSearch(filters.q ?? "");
    setIpDraft(filters.ip ?? "");
    load("");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  // Only the newest page refreshes itself; older pages hold still to read.
  useEffect(() => {
    if (cursor) return;
    const t = setInterval(() => load(""), POLL_MS);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, cursor]);

  // Debounced free-text search.
  useEffect(() => {
    const v = search.trim();
    if (v === (filters.q ?? "")) return;
    const t = setTimeout(() => onChange({ ...filters, q: v || undefined }), 350);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  function set(patch: Partial<RequestFilters>) {
    onChange({ ...filters, ...patch });
  }
  function older() {
    if (!page?.next) return;
    setTrail((t) => [...t, cursor]);
    setCursor(page.next);
    load(page.next);
  }
  function newer() {
    const t = [...trail];
    const prev = t.pop() ?? "";
    setTrail(t);
    setCursor(prev);
    load(prev);
  }
  // A filter from the details dialog replaces everything but the time range.
  function applyFromDetail(f: Partial<RequestFilters>) {
    onChange({ range: filters.range, from: filters.from, to: filters.to, ...f });
  }

  const hostName = (id: string) => (hosts.find((h) => h.id === id)?.domain_names ?? [])[0];
  const events = page?.events ?? [];
  const first = trail.length * PAGE + 1;
  const chips = activeChips(filters, hostName);

  return (
    <div>
      <div className="card card-pad">
        <div className="flex flex-wrap items-center gap-3">
          <Segmented
            label="Time range"
            value={filters.range}
            options={[
              ["1h", "1h"],
              ["24h", "24h"],
              ["7d", "7d"],
              ["30d", "30d"],
            ]}
            onChange={(v) => set({ range: v as RequestRange, from: undefined, to: undefined })}
          />
          <Segmented
            label="Outcome"
            value={filters.outcome ?? ""}
            options={[
              ["", "All"],
              ["blocked", "Blocked"],
              ["flagged", "Flagged"],
              ["served", "Served"],
            ]}
            onChange={(v) => set({ outcome: (v || undefined) as RequestFilters["outcome"] })}
          />
          <div className="ml-auto w-full sm:w-72">
            <SearchInput value={search} onChange={setSearch} placeholder="Path, domain, IP or request ID" label="Search requests" />
          </div>
        </div>
        <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <select aria-label="Country" className="input text-sm" value={filters.country ?? ""} onChange={(e) => set({ country: e.target.value || undefined })}>
            <option value="">All countries</option>
            {COUNTRIES.map((c) => (
              <option key={c.code} value={c.code}>
                {c.name} ({c.code})
              </option>
            ))}
          </select>
          <select aria-label="Blocked by" className="input text-sm" value={filters.stage ?? ""} onChange={(e) => set({ stage: e.target.value || undefined })}>
            <option value="">Any layer</option>
            {STAGES.map((s) => (
              <option key={s} value={s}>
                Blocked by {stageLabel(s)}
              </option>
            ))}
          </select>
          <select aria-label="Status" className="input text-sm" value={filters.status ?? ""} onChange={(e) => set({ status: e.target.value || undefined })}>
            <option value="">Any status</option>
            {["2", "3", "4", "5"].map((c) => (
              <option key={c} value={c}>
                {c}xx
              </option>
            ))}
          </select>
          <select aria-label="Method" className="input text-sm" value={filters.method ?? ""} onChange={(e) => set({ method: e.target.value || undefined })}>
            <option value="">Any method</option>
            {METHODS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              set({ ip: ipDraft.trim() || undefined });
            }}
          >
            <input
              aria-label="Client IP (press Enter)"
              className="input font-mono text-sm"
              placeholder="Client IP, Enter"
              value={ipDraft}
              onChange={(e) => setIpDraft(e.target.value)}
              onBlur={() => {
                if (ipDraft.trim() !== (filters.ip ?? "")) set({ ip: ipDraft.trim() || undefined });
              }}
            />
          </form>
        </div>
        {chips.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-2" aria-label="Active filters">
            {chips.map((c) => (
              <span key={c.key} className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 py-0.5 pl-3 pr-1 text-xs font-semibold text-accent">
                {c.label}
                <button type="button" className="rounded-full p-0.5 hover:bg-accent/20" aria-label={`Remove filter ${c.label}`} onClick={() => set(c.clear)}>
                  <X size={12} aria-hidden />
                </button>
              </span>
            ))}
            <button type="button" className="text-xs font-semibold text-dim hover:text-fg" onClick={() => onChange({ range: "24h" })}>
              Clear filters
            </button>
          </div>
        )}
      </div>

      {page?.log_mode === "off" && (
        <div className="mt-4">
          <Notice tone="warn" title="The request log is off">
            Set <span className="mono">AEGIS_REQUEST_LOG=all</span> (or <span className="mono">security</span>) on the API to keep requests. The live feed
            still shows the most recent ones.
          </Notice>
        </div>
      )}
      {page?.log_mode === "security" && (
        <p className="mt-3 text-xs text-faint">
          Only blocked and WAF-flagged requests are kept (<span className="mono">AEGIS_REQUEST_LOG=security</span>).
        </p>
      )}

      <div className="mb-3 mt-5 flex flex-wrap items-center gap-3">
        <h2 className="section-title">
          {page ? `${page.count_capped ? "10,000+" : fmtInt(page.count)} ${page.count === 1 ? "request" : "requests"}` : "Requests"}
        </h2>
        <span className="text-xs text-faint">Newest first{cursor ? "" : ", refreshes every 10 seconds"}</span>
        <button type="button" className="btn btn-ghost btn-sm ml-auto" onClick={() => load()} disabled={busy} aria-label="Refresh">
          <RefreshCw size={14} className={busy ? "animate-spin" : ""} aria-hidden /> Refresh
        </button>
      </div>

      {err ? (
        <ErrorState message={err} onRetry={() => load()} />
      ) : page === null ? (
        <div className="card card-pad">
          <Loading rows={6} label="Loading requests" />
        </div>
      ) : events.length === 0 ? (
        <Empty body={chips.length > 0 ? "No requests match these filters in this range." : "No requests in this range yet."} />
      ) : (
        <>
          <Table
            columns={[
              { label: "Time" },
              { label: "Status" },
              { label: "Outcome" },
              { label: "Host" },
              { label: "Request" },
              { label: "Client" },
              { label: "ms", align: "right" },
            ]}
          >
            {events.map((e, i) => {
              const o = outcomeOf(e);
              return (
                <tr key={e.id || `${e.timestamp_unix_ms}-${i}`} className="table-row cursor-pointer" onClick={() => setOpen(e)}>
                  <td className="whitespace-nowrap py-2.5 pr-5 font-mono text-xs text-faint">
                    {filters.range === "1h" || filters.range === "24h" ? "" : `${fmtDate(e.timestamp_unix_ms).slice(5)} `}
                    {fmtTime(e.timestamp_unix_ms)}
                  </td>
                  <td className="py-2.5 pr-5">
                    <StatusPill tone={statusTone(e.status)}>{e.status || "—"}</StatusPill>
                  </td>
                  <td className="whitespace-nowrap py-2.5 pr-5 text-xs">
                    <span className={o.tone === "danger" ? "font-semibold text-danger" : o.tone === "warn" ? "font-semibold text-warn" : "text-faint"}>
                      {o.short}
                    </span>
                  </td>
                  <td className="max-w-[12rem] truncate py-2.5 pr-5">{e.domain || "—"}</td>
                  <td className="max-w-[22rem] py-2.5 pr-5">
                    <button
                      type="button"
                      className="block max-w-full truncate text-left font-mono text-xs text-dim hover:text-fg"
                      onClick={(ev) => {
                        ev.stopPropagation();
                        setOpen(e);
                      }}
                      aria-label={`Details for ${e.method} ${e.path} at ${fmtTime(e.timestamp_unix_ms)}`}
                    >
                      <span className="text-faint">{e.method}</span> {e.path || "/"}
                      {e.query ? <span className="text-faint">?{e.query}</span> : null}
                    </button>
                  </td>
                  <td className="whitespace-nowrap py-2.5 pr-5 font-mono text-xs text-dim">
                    {e.client_ip || "—"}
                    {e.country && <span className="ml-1.5 text-faint">{e.country}</span>}
                  </td>
                  <td className="py-2.5 text-right font-mono text-xs">{e.duration_ms?.toFixed(1)}</td>
                </tr>
              );
            })}
          </Table>
          <div className="mt-3 flex items-center justify-between gap-3 text-sm text-dim">
            <span>
              Showing {fmtInt(first)}–{fmtInt(first + events.length - 1)}
              {page.count_capped ? " of 10,000+" : ` of ${fmtInt(page.count)}`}
            </span>
            <div className="flex gap-2">
              <button type="button" className="btn btn-secondary btn-sm" disabled={trail.length === 0 || busy} onClick={newer}>
                <ChevronLeft size={14} aria-hidden /> Newer
              </button>
              <button type="button" className="btn btn-secondary btn-sm" disabled={!page.next || busy} onClick={older}>
                Older <ChevronRight size={14} aria-hidden />
              </button>
            </div>
          </div>
        </>
      )}

      {open && <RequestDetail event={open} onClose={() => setOpen(null)} onFilter={applyFromDetail} />}
    </div>
  );
}

function Segmented({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: [string, string][];
  onChange: (v: string) => void;
}) {
  return (
    <div role="group" aria-label={label} className="flex gap-0.5 rounded-[11px] border border-border bg-panel p-[3px]">
      {options.map(([v, text]) => (
        <button
          key={v || "all"}
          type="button"
          aria-pressed={value === v}
          onClick={() => onChange(v)}
          className={`h-[30px] rounded-lg px-3 text-[13px] font-bold transition-colors ${
            value === v ? "bg-accent text-ink" : "text-dim hover:text-fg"
          }`}
        >
          {text}
        </button>
      ))}
    </div>
  );
}

type Chip = { key: string; label: string; clear: Partial<RequestFilters> };

// Filters that have no control of their own on the bar (they arrive from a
// click elsewhere) or that are easy to miss get a removable chip.
function activeChips(f: RequestFilters, hostName: (id: string) => string | undefined): Chip[] {
  const out: Chip[] = [];
  if (f.range === "custom" && f.from) {
    const a = new Date(f.from);
    const b = f.to ? new Date(f.to) : null;
    out.push({
      key: "range",
      label: `${fmtDate(a)} ${fmtTime(a).slice(0, 5)}${b ? `–${fmtTime(b).slice(0, 5)}` : ""}`,
      clear: { range: "24h", from: undefined, to: undefined },
    });
  }
  if (f.host_id) out.push({ key: "host", label: `Host ${hostName(f.host_id) ?? f.host_id.slice(0, 8)}`, clear: { host_id: undefined } });
  if (f.country) out.push({ key: "country", label: countryName(f.country), clear: { country: undefined } });
  if (f.ip) out.push({ key: "ip", label: `IP ${f.ip}`, clear: { ip: undefined } });
  if (f.rule) out.push({ key: "rule", label: `Rule ${f.rule}`, clear: { rule: undefined } });
  if (f.stage) out.push({ key: "stage", label: `Blocked by ${stageLabel(f.stage)}`, clear: { stage: undefined } });
  if (f.outcome) out.push({ key: "outcome", label: f.outcome[0].toUpperCase() + f.outcome.slice(1), clear: { outcome: undefined } });
  if (f.status) out.push({ key: "status", label: `${f.status}xx`, clear: { status: undefined } });
  if (f.method) out.push({ key: "method", label: f.method, clear: { method: undefined } });
  if (f.path) out.push({ key: "path", label: `Path ${f.path}`, clear: { path: undefined } });
  if (f.q) out.push({ key: "q", label: `“${f.q}”`, clear: { q: undefined } });
  return out;
}
