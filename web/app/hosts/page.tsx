"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { Download, LayoutGrid, List, Lock, LockOpen, Plus, ShieldAlert, Upload } from "lucide-react";
import { api, isUnauthorized } from "@/lib/api";
import type { AccessList, Certificate, Host, HostInput, RollupRow, WAFProfile } from "@/lib/types";
import { AppShell } from "@/components/app-shell";
import { HostDialog } from "@/components/host-dialog";
import { Sparkline } from "@/components/charts";
import { ActionMenu, Empty, ErrorState, Loading, PageHeader, Pager, SearchInput, StatusPill, usePaged, type Tone } from "@/components/ui";
import { daysUntil, fmtInt, fmtLatency } from "@/lib/format";
import { trafficByHost, type HostTraffic } from "@/lib/rollups";
import { POLL_MS } from "@/lib/poll";

type View = "cards" | "list";
type KindFilter = "all" | "proxy" | "redirect" | "stream" | "dead" | "attention";
const VIEW_KEY = "aegis.hosts.view";

export default function HostsPage() {
  return (
    <AppShell>
      <Suspense fallback={<Loading rows={6} label="Loading hosts" />}>
        <Hosts />
      </Suspense>
    </AppShell>
  );
}

function Hosts() {
  const router = useRouter();
  const params = useSearchParams();
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [wafProfiles, setWafProfiles] = useState<WAFProfile[]>([]);
  const [lists, setLists] = useState<AccessList[]>([]);
  const [rollups, setRollups] = useState<RollupRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<Host | null>(null);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<KindFilter>("all");
  const [view, setView] = useState<View>("cards");

  // Remembered per browser; the page renders fine without it.
  useEffect(() => {
    try {
      const v = localStorage.getItem(VIEW_KEY);
      if (v === "cards" || v === "list") setView(v);
    } catch {
      /* storage unavailable */
    }
  }, []);
  function chooseView(v: View) {
    setView(v);
    try {
      localStorage.setItem(VIEW_KEY, v);
    } catch {
      /* storage unavailable */
    }
  }

  async function load() {
    try {
      const from = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
      const [h, c, w, a, r] = await Promise.all([
        api.hosts(),
        api.certificates().catch(() => [] as Certificate[]),
        api.wafProfiles().catch(() => [] as WAFProfile[]),
        api.accessLists().catch(() => [] as AccessList[]),
        api.analyticsRollups("hourly", { from }).catch(() => ({ rows: [] as RollupRow[] })),
      ]);
      setHosts(h);
      setCerts(c);
      setWafProfiles(w);
      setLists(a);
      setRollups(r.rows ?? []);
      setErr(null);
    } catch (e) {
      if (isUnauthorized(e)) return;
      setErr(e instanceof Error ? e.message : "Failed to load hosts");
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, []);

  // /hosts?new=1 (the Overview "Add host" button) opens the dialog once.
  useEffect(() => {
    if (params.get("new") === "1") {
      setEditing(null);
      setDialogOpen(true);
      router.replace("/hosts");
    }
  }, [params, router]);

  // Bulk actions: selection is by host id and survives filter changes.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkMsg, setBulkMsg] = useState<string | null>(null);
  const [importMsg, setImportMsg] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  function toggleSelected(id: string) {
    setSelected((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function runBulk(action: "enable" | "disable" | "delete" | "set_access_list" | "set_waf_profile", extra?: { access_list_id?: string | null; waf_profile_id?: string | null }) {
    const ids = Array.from(selected);
    if (ids.length === 0) return;
    const n = ids.length;
    const noun = `${n} host${n === 1 ? "" : "s"}`;
    if (action === "delete" && !window.confirm(`Delete ${noun}? Their domains stop being served immediately. This cannot be undone.`)) return;
    if (action === "disable" && !window.confirm(`Disable ${noun}? Visitors get "no such host" until they are enabled again.`)) return;
    setBulkBusy(true);
    setBulkMsg(null);
    try {
      const out = await api.bulkHosts({ ids, action, ...extra });
      const verb = { enable: "enabled", disable: "disabled", delete: "deleted", set_access_list: "updated", set_waf_profile: "updated" }[action];
      setBulkMsg(out.failed.length ? `${out.done} ${verb}; ${out.failed.length} failed: ${out.failed.map((f) => f.error).slice(0, 3).join("; ")}` : `${out.done} host${out.done === 1 ? "" : "s"} ${verb}.`);
      setSelected(new Set());
      await load();
    } catch (e) {
      setBulkMsg(e instanceof Error ? e.message : "Bulk action failed");
    } finally {
      setBulkBusy(false);
    }
  }

  async function onImportFile(file: File) {
    setImportMsg(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      setImportMsg("That file is not JSON.");
      return;
    }
    const list = Array.isArray(parsed) ? parsed : (parsed as { hosts?: unknown[] })?.hosts;
    if (!Array.isArray(list) || list.length === 0) {
      setImportMsg("No hosts found in that file. Export from Aegis produces the expected shape.");
      return;
    }
    const update = window.confirm(`Import ${list.length} host${list.length === 1 ? "" : "s"}.\n\nOK: replace hosts here whose domain already exists.\nCancel: skip those and only add new ones.`);
    try {
      const out = await api.importHosts(list, update ? "update" : "skip");
      const parts = [`${out.created} added`, `${out.updated} replaced`, `${out.skipped} skipped`];
      if (out.problems.length) parts.push(`${out.problems.length} not imported: ` + out.problems.slice(0, 4).map((p) => `${(p.domains ?? []).join(", ") || "entry"} (${p.error})`).join("; "));
      setImportMsg(parts.join(", ") + ".");
      await load();
    } catch (e) {
      setImportMsg(e instanceof Error ? e.message : "Import failed");
    }
  }

  async function onToggle(h: Host) {
    if (h.enabled && !confirm(`Disable ${h.domain_names[0] ?? "this host"}? Visitors get "no such host" until it is enabled again.`)) return;
    try {
      await api.updateHost(h.id, toInput(h, { enabled: !h.enabled }));
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Update failed");
    }
  }

  const traffic = useMemo(() => trafficByHost(rollups), [rollups]);
  const rows = useMemo(
    () => (hosts ?? []).map((h) => describe(h, { certs, wafProfiles, lists, traffic: traffic[h.id] })),
    [hosts, certs, wafProfiles, lists, traffic],
  );

  const counts = useMemo(() => {
    const c: Record<KindFilter, number> = { all: rows.length, proxy: 0, redirect: 0, stream: 0, dead: 0, attention: 0 };
    for (const r of rows) {
      c[r.host.kind || "proxy"] += 1;
      if (r.attention) c.attention += 1;
    }
    return c;
  }, [rows]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (kind === "attention" ? !r.attention : kind !== "all" && (r.host.kind || "proxy") !== kind) return false;
      if (!needle) return true;
      return [r.host.domain_names.join(" "), r.destination, r.kindLabel, r.protections.map((p) => p.label).join(" ")]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [rows, q, kind]);
  const paged = usePaged(filtered, view === "cards" ? 24 : 25);

  function openNew() {
    setEditing(null);
    setDialogOpen(true);
  }
  function openEdit(h: Host) {
    setEditing(h);
    setDialogOpen(true);
  }

  const filters: { id: KindFilter; label: string }[] = [
    { id: "all", label: "All" },
    { id: "proxy", label: "Proxy" },
    { id: "redirect", label: "Redirect" },
    { id: "stream", label: "Stream" },
    { id: "dead", label: "404" },
    { id: "attention", label: "Needs attention" },
  ];

  return (
    <>
      <PageHeader
        title="Hosts"
        description="Every domain and stream Aegis serves, the protection on it, and its traffic over the last 24 hours."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept="application/json,.json"
              className="sr-only"
              aria-label="Import hosts from a JSON export"
              onChange={(e) => {
                const f = e.target.files?.[0];
                e.target.value = "";
                if (f) onImportFile(f);
              }}
            />
            <button type="button" className="btn btn-secondary" onClick={() => fileRef.current?.click()} title="Import hosts from a JSON export">
              <Upload size={16} aria-hidden /> Import
            </button>
            <a className="btn btn-secondary" href={api.exportHostsURL()} download title="Download every host as JSON">
              <Download size={16} aria-hidden /> Export
            </a>
            <button type="button" className="btn btn-primary" onClick={openNew}>
              <Plus size={16} strokeWidth={2.4} aria-hidden /> Add host
            </button>
          </div>
        }
      />

      {importMsg && (
        <div className="mt-4 rounded-xl border border-border bg-panel px-4 py-3 text-sm" role="status">
          {importMsg}
        </div>
      )}

      {err && (
        <div className="mt-4">
          <ErrorState message={err} onRetry={load} />
        </div>
      )}

      {hosts === null ? (
        <div className="card card-pad mt-6">
          <Loading rows={6} label="Loading hosts" />
        </div>
      ) : hosts.length === 0 ? (
        <div className="mt-6">
          <Empty
            title="No hosts yet"
            body="Point a domain at an upstream and Aegis handles TLS, the security pipeline, and delivery."
            action={
              <button type="button" className="btn btn-primary" onClick={openNew}>
                <Plus size={16} strokeWidth={2.4} aria-hidden /> Add your first host
              </button>
            }
          />
        </div>
      ) : (
        <>
          <div className="mt-6 flex flex-wrap items-center gap-2.5">
            <div role="group" aria-label="Filter by kind" className="flex flex-wrap gap-2">
              {filters
                .filter((f) => f.id === "all" || f.id === "attention" || counts[f.id] > 0)
                .map((f) => {
                  const on = kind === f.id;
                  return (
                    <button
                      key={f.id}
                      type="button"
                      aria-pressed={on}
                      onClick={() => setKind(f.id)}
                      className={`h-9 rounded-full px-3.5 text-[13px] font-bold transition-colors ${
                        on ? "bg-accent text-ink" : "border border-border-strong text-dim hover:border-border-hover hover:text-fg"
                      }`}
                    >
                      {f.label} <span className={on ? "" : "text-faint"}>{counts[f.id]}</span>
                    </button>
                  );
                })}
            </div>
            <div className="ml-auto flex w-full items-center gap-2.5 sm:w-auto">
              <div className="min-w-0 flex-1 sm:w-72 sm:flex-none">
                <SearchInput value={q} onChange={setQ} placeholder="Filter by domain, upstream, protection" label="Filter hosts" />
              </div>
              <div role="group" aria-label="Layout" className="flex gap-0.5 rounded-[11px] border border-border bg-panel p-[3px]">
                <ViewButton on={view === "cards"} label="Card view" onClick={() => chooseView("cards")}>
                  <LayoutGrid size={16} aria-hidden />
                </ViewButton>
                <ViewButton on={view === "list"} label="List view" onClick={() => chooseView("list")}>
                  <List size={16} aria-hidden />
                </ViewButton>
              </div>
            </div>
          </div>

          {(selected.size > 0 || bulkMsg) && (
            <div className="mt-4 flex flex-wrap items-center gap-2 rounded-xl border border-accent/30 bg-accent/5 px-4 py-2.5 text-sm" role="region" aria-label="Bulk actions">
              {selected.size > 0 ? (
                <>
                  <span className="font-semibold">{selected.size} selected</span>
                  <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set(filtered.map((r) => r.host.id)))}>
                    Select all {filtered.length}
                  </button>
                  <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}>
                    Clear
                  </button>
                  <span className="mx-1 h-5 w-px bg-border" aria-hidden />
                  <button type="button" className="btn btn-secondary btn-sm" disabled={bulkBusy} onClick={() => runBulk("enable")}>
                    Enable
                  </button>
                  <button type="button" className="btn btn-secondary btn-sm" disabled={bulkBusy} onClick={() => runBulk("disable")}>
                    Disable
                  </button>
                  <select
                    className="input h-8 !w-44 py-0 text-xs"
                    aria-label="Set access list on selected hosts"
                    disabled={bulkBusy}
                    value=""
                    onChange={(e) => {
                      const v = e.target.value;
                      if (v === "") return;
                      runBulk("set_access_list", { access_list_id: v === "__none" ? null : v });
                    }}
                  >
                    <option value="">Access list…</option>
                    <option value="__none">No access list</option>
                    {lists.map((l) => (
                      <option key={l.id} value={l.id}>
                        {l.name}
                      </option>
                    ))}
                  </select>
                  <select
                    className="input h-8 !w-44 py-0 text-xs"
                    aria-label="Set WAF profile on selected hosts"
                    disabled={bulkBusy}
                    value=""
                    onChange={(e) => {
                      const v = e.target.value;
                      if (v === "") return;
                      runBulk("set_waf_profile", { waf_profile_id: v === "__none" ? null : v });
                    }}
                  >
                    <option value="">WAF profile…</option>
                    <option value="__none">No WAF</option>
                    {wafProfiles.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                  <button type="button" className="btn btn-ghost btn-sm ml-auto text-danger" disabled={bulkBusy} onClick={() => runBulk("delete")}>
                    Delete
                  </button>
                </>
              ) : (
                <span role="status">{bulkMsg}</span>
              )}
            </div>
          )}

          <div className="mt-5">
            {filtered.length === 0 ? (
              <Empty body="No hosts match that filter." />
            ) : view === "cards" ? (
              <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
                {paged.pageItems.map((r) => (
                  <HostCard key={r.host.id} r={r} onEdit={() => openEdit(r.host)} onToggle={() => onToggle(r.host)} checked={selected.has(r.host.id)} onCheck={() => toggleSelected(r.host.id)} />
                ))}
              </div>
            ) : (
              <HostList rows={paged.pageItems} onEdit={openEdit} onToggle={onToggle} selected={selected} onCheck={toggleSelected} />
            )}
            <Pager {...paged} noun={filtered.length === 1 ? "host" : "hosts"} />
          </div>
        </>
      )}

      {dialogOpen && (
        <HostDialog
          host={editing}
          onClose={() => setDialogOpen(false)}
          onSaved={async () => {
            setDialogOpen(false);
            await load();
          }}
        />
      )}
    </>
  );
}

function ViewButton({ on, label, onClick, children }: { on: boolean; label: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={on}
      aria-label={label}
      title={label}
      onClick={onClick}
      className={`flex h-[30px] w-8 items-center justify-center rounded-lg border transition-colors ${
        on ? "border-border-strong bg-panel-2 text-fg" : "border-transparent text-faint hover:text-fg"
      }`}
    >
      {children}
    </button>
  );
}

// Everything the card and list views show about one host.
type Row = {
  host: Host;
  name: string;
  initials: string;
  kindLabel: string;
  destination: string;
  protections: { label: string; tone: Tone }[];
  tls: { label: string; tone: Tone; secure: boolean };
  status: { label: string; tone: Tone };
  traffic?: HostTraffic;
  attention: boolean;
};

function describe(
  h: Host,
  ctx: { certs: Certificate[]; wafProfiles: WAFProfile[]; lists: AccessList[]; traffic?: HostTraffic },
): Row {
  const name = h.domain_names[0] ?? "(unnamed)";
  const bare = name.replace(/^\*\./, "").replace(/^www\./, "");
  const initials = bare.replace(/[^a-z0-9]/gi, "").slice(0, 2).toUpperCase() || "—";

  const protections: Row["protections"] = [];
  if (h.waf_profile_id) {
    const p = ctx.wafProfiles.find((w) => w.id === h.waf_profile_id);
    protections.push({ label: p ? `WAF · ${p.name}` : "WAF", tone: "accent" });
  }
  if (h.crowdsec_enabled) protections.push({ label: "CrowdSec", tone: "accent" });
  if ((h.geo_allow?.length ?? 0) + (h.geo_deny?.length ?? 0) > 0) protections.push({ label: "GeoIP", tone: "accent" });
  if (h.rate_limit_rps > 0) protections.push({ label: `${h.rate_limit_rps} rps limit`, tone: "accent" });
  if (h.access_list_id) {
    const a = ctx.lists.find((l) => l.id === h.access_list_id);
    protections.push({ label: a ? `ACL · ${a.name}` : "Access list", tone: "accent" });
  }

  let tls: Row["tls"];
  if (h.kind === "stream") tls = { label: "Passthrough", tone: "neutral", secure: false };
  else if (h.kind === "redirect" || h.kind === "dead") tls = h.tls_mode === "none" ? { label: "HTTP", tone: "neutral", secure: false } : { label: "HTTPS", tone: "neutral", secure: true };
  else if (h.tls_mode === "none") tls = { label: "HTTP only", tone: "warn", secure: false };
  else {
    const cert = h.cert_id ? ctx.certs.find((c) => c.id === h.cert_id) : coveringCert(h, ctx.certs);
    const left = cert ? daysUntil(cert.expires_at) : null;
    const issuer = !cert ? (h.tls_mode === "auto" ? "Let’s Encrypt" : "Custom") : issuerLabel(cert.issuer);
    if (left === null) tls = { label: h.tls_mode === "auto" ? `${issuer} · pending` : issuer, tone: "neutral", secure: true };
    else if (left < 0) tls = { label: `Expired ${-left}d ago`, tone: "danger", secure: false };
    else if (left <= 14) tls = { label: `${issuer} · ${left}d left`, tone: "warn", secure: true };
    else tls = { label: `${issuer} · ${left}d`, tone: "neutral", secure: true };
  }

  let status: Row["status"];
  if (!h.enabled) status = { label: "Disabled", tone: "neutral" };
  else if (tls.tone === "danger") status = { label: "Cert expired", tone: "danger" };
  else if ((ctx.traffic?.requests ?? 0) === 0) status = { label: "Idle", tone: "neutral" };
  else status = { label: "Live", tone: "ok" };

  const attention =
    h.enabled && (tls.tone === "danger" || tls.tone === "warn" || (h.kind === "proxy" && !h.waf_profile_id));

  return {
    host: h,
    name,
    initials,
    kindLabel: kindLabel(h.kind),
    destination: destination(h),
    protections,
    tls,
    status,
    traffic: ctx.traffic,
    attention,
  };
}

// An auto host without a bound cert uses the newest cert that covers its
// first domain, the same rule the config push applies.
function coveringCert(h: Host, certs: Certificate[]) {
  const d = h.domain_names[0];
  if (!d) return undefined;
  const covers = (pattern: string) =>
    pattern === d || (pattern.startsWith("*.") && d.endsWith(pattern.slice(1)) && d.split(".").length === pattern.split(".").length);
  return certs
    .filter((c) => (c.domains ?? []).some(covers))
    .sort((a, b) => (a.expires_at < b.expires_at ? 1 : -1))[0];
}

function issuerLabel(i: string) {
  if (i === "letsencrypt") return "Let’s Encrypt";
  if (i === "selfsigned") return "Self-signed";
  if (i === "custom") return "Custom";
  return i;
}

function SelectBox({ checked, onChange, label }: { checked: boolean; onChange: () => void; label: string }) {
  return (
    <input
      type="checkbox"
      className="h-4 w-4 shrink-0 cursor-pointer accent-[var(--accent)]"
      checked={checked}
      onChange={onChange}
      aria-label={label}
    />
  );
}

function HostCard({ r, onEdit, onToggle, checked, onCheck }: { r: Row; onEdit: () => void; onToggle: () => void; checked: boolean; onCheck: () => void }) {
  const t = r.traffic;
  return (
    <article className={`card flex flex-col gap-4 p-5 transition-colors hover:border-border-strong ${checked ? "border-accent/60" : ""} ${r.host.enabled ? "" : "opacity-60"}`}>
      <div className="flex items-start gap-3">
        <div className="flex items-center self-center">
          <SelectBox checked={checked} onChange={onCheck} label={`Select ${r.name}`} />
        </div>
        <Avatar initials={r.initials} />
        <div className="min-w-0 flex-1">
          <button type="button" onClick={onEdit} className="block max-w-full truncate text-left font-display text-base font-semibold hover:text-accent">
            {r.name}
            {r.host.domain_names.length > 1 && <span className="ml-1.5 text-xs font-normal text-faint">+{r.host.domain_names.length - 1}</span>}
          </button>
          <div className="mt-0.5 truncate font-mono text-xs text-faint" title={r.destination}>
            {r.destination}
          </div>
        </div>
        <StatusPill tone={r.status.tone}>{r.status.label}</StatusPill>
        <ActionMenu
          label={`Actions for ${r.name}`}
          items={[
            { label: "Edit host", onSelect: onEdit },
            { label: r.host.enabled ? "Disable" : "Enable", onSelect: onToggle },
          ]}
        />
      </div>

      <div className="h-10">
        {t && t.requests > 0 ? (
          <Sparkline values={t.hourly} width={400} height={40} label={`Requests per hour for ${r.name}, last 24 hours`} />
        ) : (
          <div className="flex h-10 items-center border-y border-dashed border-border text-xs text-faint">No traffic in the last 24 hours</div>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-faint">
        <span>
          <span className="font-mono text-fg">{t ? fmtRate(t.rps) : "0"}</span> req/s
        </span>
        <span>
          <span className="font-mono text-fg">{fmtLatency(t?.avgMs)}</span> avg
        </span>
        <span>
          <span className="font-mono text-fg">{fmtInt(t?.blocked ?? 0)}</span> blocked
        </span>
        <TlsTag tls={r.tls} className="ml-auto" />
      </div>

      <div className="flex min-h-[24px] flex-wrap gap-1.5 border-t border-border pt-3.5">
        <ProtectionChips r={r} />
      </div>
    </article>
  );
}

function HostList({ rows, onEdit, onToggle, selected, onCheck }: { rows: Row[]; onEdit: (h: Host) => void; onToggle: (h: Host) => void; selected: Set<string>; onCheck: (id: string) => void }) {
  return (
    <div className="card overflow-x-auto">
      <table className="data-table w-full min-w-[60rem] text-sm">
        <thead>
          <tr className="border-b border-border text-left text-xs font-semibold text-faint">
            <th scope="col" className="w-8 py-3 pr-2">
              <span className="sr-only">Select</span>
            </th>
            <th scope="col" className="py-3 pr-4 font-semibold">Host</th>
            <th scope="col" className="py-3 pr-4 font-semibold">Protection</th>
            <th scope="col" className="py-3 pr-4 font-semibold">Certificate</th>
            <th scope="col" className="py-3 pr-4 font-semibold">Traffic 24h</th>
            <th scope="col" className="py-3 pr-4 text-right font-semibold">Avg</th>
            <th scope="col" className="py-3 pr-4 font-semibold">Status</th>
            <th scope="col" className="py-3">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.host.id} className={`table-row ${r.host.enabled ? "" : "opacity-60"}`}>
              <td className="py-3 pr-2">
                <SelectBox checked={selected.has(r.host.id)} onChange={() => onCheck(r.host.id)} label={`Select ${r.name}`} />
              </td>
              <td className="py-3 pr-4">
                <div className="flex items-center gap-3">
                  <Avatar initials={r.initials} small />
                  <div className="min-w-0">
                    <button type="button" onClick={() => onEdit(r.host)} className="block max-w-[22rem] truncate text-left font-display text-[15px] font-semibold hover:text-accent">
                      {r.name}
                      {r.host.domain_names.length > 1 && <span className="ml-1.5 text-xs font-normal text-faint">+{r.host.domain_names.length - 1}</span>}
                    </button>
                    <div className="max-w-[22rem] truncate font-mono text-xs text-faint" title={r.destination}>
                      <span className="capitalize">{r.kindLabel}</span> → {r.destination}
                    </div>
                  </div>
                </div>
              </td>
              <td className="py-3 pr-4">
                <div className="flex max-w-[16rem] flex-wrap gap-1.5">
                  <ProtectionChips r={r} />
                </div>
              </td>
              <td className="py-3 pr-4">
                <TlsTag tls={r.tls} />
              </td>
              <td className="py-3 pr-4">
                <div className="flex items-center gap-2.5">
                  <div className="w-24">
                    {r.traffic && r.traffic.requests > 0 ? <Sparkline values={r.traffic.hourly} width={96} height={26} /> : <span className="text-xs text-faint">—</span>}
                  </div>
                  <span className="font-mono text-xs text-dim">{r.traffic ? `${fmtRate(r.traffic.rps)}/s` : ""}</span>
                </div>
              </td>
              <td className="py-3 pr-4 text-right font-mono text-xs text-dim">
                {fmtLatency(r.traffic?.avgMs)}
              </td>
              <td className="py-3 pr-4">
                <StatusPill tone={r.status.tone}>{r.status.label}</StatusPill>
              </td>
              <td className="py-3 text-right">
                <ActionMenu
                  label={`Actions for ${r.name}`}
                  items={[
                    { label: "Edit host", onSelect: () => onEdit(r.host) },
                    { label: r.host.enabled ? "Disable" : "Enable", onSelect: () => onToggle(r.host) },
                  ]}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Avatar({ initials, small }: { initials: string; small?: boolean }) {
  return (
    <div
      aria-hidden
      className={`flex shrink-0 items-center justify-center border border-border-strong bg-panel-2 font-display font-bold text-dim ${
        small ? "h-9 w-9 rounded-[10px] text-[13px]" : "h-10 w-10 rounded-[11px] text-sm"
      }`}
    >
      {initials}
    </div>
  );
}

function ProtectionChips({ r }: { r: Row }) {
  if (r.protections.length === 0) {
    if (r.host.kind !== "proxy") return <span className="text-xs text-faint">No protection layers</span>;
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-warn">
        <ShieldAlert size={14} aria-hidden /> Unprotected
      </span>
    );
  }
  return (
    <>
      {r.protections.map((p) => (
        <span key={p.label} className="rounded-md bg-accent/10 px-2 py-0.5 text-[11px] font-bold text-accent">
          {p.label}
        </span>
      ))}
    </>
  );
}

function TlsTag({ tls, className = "" }: { tls: Row["tls"]; className?: string }) {
  const color = { neutral: "text-dim", warn: "text-warn", danger: "text-danger", ok: "text-ok", accent: "text-accent" }[tls.tone];
  const Icon = tls.secure ? Lock : LockOpen;
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap text-xs ${color} ${className}`}>
      <Icon size={13} aria-hidden /> {tls.label}
    </span>
  );
}

function fmtRate(n: number) {
  if (n === 0) return "0";
  if (n < 0.1) return "<0.1";
  if (n < 10) return n.toFixed(1);
  return fmtInt(n);
}

// The API replaces the whole host on update, so every field must be carried
// through or a toggle would silently strip WAF, CrowdSec, GeoIP, and limits.
function toInput(h: Host, patch: Partial<HostInput>): HostInput {
  return {
    kind: h.kind || "proxy",
    domain_names: h.domain_names,
    upstream_scheme: h.upstream_scheme,
    upstream_host: h.upstream_host,
    upstream_port: h.upstream_port,
    upstreams: h.upstreams,
    enabled: h.enabled,
    tls_mode: h.tls_mode,
    cert_id: h.cert_id,
    force_https: h.force_https,
    hsts: h.hsts,
    websocket_support: h.websocket_support,
    redirect_url: h.redirect_url,
    redirect_code: h.redirect_code,
    request_headers: h.request_headers,
    response_headers: h.response_headers,
    access_list_id: h.access_list_id,
    listen_protocol: h.listen_protocol,
    listen_port: h.listen_port,
    waf_profile_id: h.waf_profile_id,
    rate_limit_rps: h.rate_limit_rps,
    rate_limit_burst: h.rate_limit_burst,
    geo_allow: h.geo_allow,
    geo_deny: h.geo_deny,
    crowdsec_enabled: h.crowdsec_enabled,
    upstream_host_header: h.upstream_host_header,
    lb_policy: h.lb_policy,
    health_path: h.health_path,
    hsts_max_age: h.hsts_max_age,
    hsts_subdomains: h.hsts_subdomains,
    hsts_preload: h.hsts_preload,
    idle_timeout_seconds: h.idle_timeout_seconds,
    upstream_response_timeout_seconds: h.upstream_response_timeout_seconds,
    max_body_bytes: h.max_body_bytes,
    oidc: h.oidc,
    ...patch,
  };
}

function kindLabel(k: Host["kind"]) {
  if (k === "dead") return "404";
  return k || "proxy";
}

function destination(h: Host) {
  switch (h.kind) {
    case "redirect":
      return `${h.redirect_code || 301} → ${h.redirect_url}`;
    case "dead":
      return "Returns 404";
    case "stream":
      if (h.upstreams && h.upstreams.length > 1) {
        return `${h.listen_protocol || "tcp"}:${h.listen_port} → ${h.upstreams[0].host}:${h.upstreams[0].port} +${h.upstreams.length - 1}`;
      }
      return `${h.listen_protocol || "tcp"}:${h.listen_port} → ${h.upstream_host}:${h.upstream_port}`;
    default:
      if (h.upstreams && h.upstreams.length > 1) {
        const u = h.upstreams[0];
        return `${u.scheme || h.upstream_scheme}://${u.host}:${u.port} +${h.upstreams.length - 1} backup`;
      }
      return `${h.upstream_scheme}://${h.upstream_host}:${h.upstream_port}`;
  }
}
