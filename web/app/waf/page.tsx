"use client";

import { FormEvent, useEffect, useId, useMemo, useState } from "react";
import Link from "next/link";
import { Check, Plus, ShieldCheck, Trash2, X } from "lucide-react";
import { api, ApiError, isUnauthorized } from "@/lib/api";
import type { Host, WAFExclusion, WAFFinding, WAFPackage, WAFProfile, WAFProfileInput, WAFRule } from "@/lib/types";
import { AppShell } from "@/components/app-shell";
import { ActionMenu, Dialog, Empty, ErrorState, Field, Loading, Notice, PageHeader, StatusPill, TabPanel, Table, Tabs, useHashTab } from "@/components/ui";
import { fmtInt, fmtRelative } from "@/lib/format";
import { requestsHref } from "@/lib/requests";
import { ALL_METHODS, CRS_RESTRICTED_HEADERS, DEFAULT_CONTENT_TYPES_SUMMARY, DEFAULT_METHODS, DEFAULT_RESTRICTED_HEADERS, POLICY_RULES, WEBDAV_METHODS, excludableInput, sameSet } from "@/lib/wafpolicy";

const TAB_IDS = ["profiles", "findings"] as const;
type TabId = (typeof TAB_IDS)[number];

export default function WAFPage() {
  const [profiles, setProfiles] = useState<WAFProfile[] | null>(null);
  const [catalog, setCatalog] = useState<WAFPackage[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<WAFProfile | null>(null);
  const [startDelete, setStartDelete] = useState(false);
  const [prefill, setPrefill] = useState<WAFExclusion | null>(null);
  const [openPolicy, setOpenPolicy] = useState(false);
  const [rules, setRules] = useState<WAFRule[]>([]);
  const [tab, setTab] = useHashTab<TabId>(TAB_IDS, "profiles");
  const [findings, setFindings] = useState<WAFFinding[] | null>(null);
  const [findRange, setFindRange] = useState<"24h" | "7d" | "30d">("7d");
  const [findHost, setFindHost] = useState("");
  const [findErr, setFindErr] = useState<string | null>(null);
  const ruleByID = useMemo(() => new Map(rules.map((r) => [r.id, r])), [rules]);

  async function load() {
    // Host usage is a nicety; a failure only hides the "used by" counts.
    api.hosts().then(setHosts).catch(() => undefined);
    api.wafCatalog().then(setRules).catch(() => undefined);
    try {
      const [p, rules] = await Promise.all([api.wafProfiles(), api.wafRules()]);
      setProfiles(p);
      setCatalog(rules);
    } catch (e) {
      if (isUnauthorized(e)) return;
      setErr(e instanceof Error ? e.message : "Failed to load WAF");
    }
  }

  useEffect(() => { load(); }, []);

  async function loadFindings(range = findRange, host = findHost) {
    const ms = range === "24h" ? 864e5 : range === "7d" ? 7 * 864e5 : 30 * 864e5;
    try {
      setFindings(await api.wafFindings({ from: new Date(Date.now() - ms).toISOString(), host_id: host || undefined }));
      setFindErr(null);
    } catch (e) {
      if (isUnauthorized(e)) return;
      setFindErr(e instanceof Error ? e.message : "Failed to load findings");
    }
  }
  useEffect(() => {
    if (tab === "findings") loadFindings(findRange, findHost);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, findRange, findHost]);

  // From a finding: open the profile of the host the newest hit landed on,
  // with the exclusion filled in at the chosen scope.
  function excludeFinding(f: WAFFinding, scope: "all" | "path" | "input" | "policy") {
    const host = hosts.find((h) => h.id === f.host_id);
    const p = profiles?.find((x) => x.id === host?.waf_profile_id);
    if (!p) {
      setFindErr(`No WAF profile is attached to ${host?.domain_names?.[0] ?? "that host"} any more. Edit a profile and add rule ${f.rule_id} by hand.`);
      return;
    }
    if (scope === "policy") {
      setOpenPolicy(true);
      openEdit(p);
      return;
    }
    setPrefill({
      rule_id: f.rule_id,
      path: scope === "path" ? f.path : "",
      target: scope === "input" ? f.sample_where : "",
    });
    openEdit(p);
  }

  // /waf?profile=<id>&exclude=<rule>&target=<VAR:key>&path=<prefix> (from a
  // request's details) opens that profile with the exclusion filled in.
  useEffect(() => {
    if (!profiles) return;
    const q = new URLSearchParams(window.location.search);
    const rule = q.get("exclude");
    if (!rule) return;
    window.history.replaceState(null, "", "/waf");
    const p = profiles.find((x) => x.id === q.get("profile"));
    if (!p) {
      setErr("That request's host has no WAF profile any more. Open a profile and add the exclusion by hand.");
      return;
    }
    setPrefill({ rule_id: rule, path: q.get("path") ?? "", target: q.get("target") ?? "" });
    openEdit(p);
  }, [profiles]);

  function openEdit(p: WAFProfile | null, del = false) {
    setEditing(p);
    setStartDelete(del);
    setOpen(true);
  }

  const usage = (id: string) => hosts.filter((h) => h.waf_profile_id === id);

  return (
    <AppShell>
      <PageHeader
        title="WAF policies"
        description="Coraza with the OWASP Core Rule Set. Build a profile once, then attach it to hosts; rules are not edited per host."
        actions={
          <button type="button" className="btn btn-primary" onClick={() => openEdit(null)}>
            <Plus size={16} strokeWidth={2.4} aria-hidden /> Add profile
          </button>
        }
      />

      {err && (
        <div className="mt-6">
          <ErrorState message={err} onRetry={load} />
        </div>
      )}

      <div className="mt-6">
        <Tabs
          label="WAF sections"
          value={tab}
          onChange={setTab}
          items={[
            { id: "profiles", label: "Profiles", count: profiles?.length },
            { id: "findings", label: "Findings", count: findings?.length },
          ]}
        />
      </div>

      <TabPanel id="findings" active={tab === "findings"}>
        <FindingsPanel
          findings={findings}
          err={findErr}
          range={findRange}
          setRange={setFindRange}
          host={findHost}
          setHost={setFindHost}
          hosts={hosts}
          onExclude={excludeFinding}
          onRetry={() => loadFindings()}
        />
      </TabPanel>

      <TabPanel id="profiles" active={tab === "profiles"}>
      {profiles === null ? (
        !err && (
          <div className="card card-pad mt-6">
            <Loading rows={3} label="Loading WAF profiles" />
          </div>
        )
      ) : profiles.length === 0 ? (
        <div className="mt-6">
          <Empty
            title="No WAF profiles yet"
            body="Create a policy (mode, paranoia, packages, and exclusions), then attach it to your hosts."
            action={
              <button type="button" className="btn btn-primary" onClick={() => openEdit(null)}>
                <Plus size={16} strokeWidth={2.4} aria-hidden /> Add your first profile
              </button>
            }
          />
        </div>
      ) : (
        <div className="mt-6 grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
          {profiles.map((p) => (
            <ProfileCard
              key={p.id}
              p={p}
              catalog={catalog}
              usedBy={usage(p.id)}
              onEdit={() => openEdit(p)}
              onDelete={() => openEdit(p, true)}
            />
          ))}
        </div>
      )}
      </TabPanel>

      {open && (
        <WAFDialog
          profile={editing}
          catalog={catalog}
          startDelete={startDelete}
          usedBy={editing ? usage(editing.id).length : 0}
          prefill={prefill}
          rules={ruleByID}
          startPolicyOpen={openPolicy}
          onClose={() => { setOpen(false); setPrefill(null); setOpenPolicy(false); }}
          onSaved={async () => { setOpen(false); setPrefill(null); setOpenPolicy(false); await load(); }}
        />
      )}
    </AppShell>
  );
}

function ProfileCard({
  p,
  catalog,
  usedBy,
  onEdit,
  onDelete,
}: {
  p: WAFProfile;
  catalog: WAFPackage[];
  usedBy: Host[];
  onEdit: () => void;
  onDelete: () => void;
}) {
  const detect = p.mode === "detect";
  const pl = p.paranoia || 1;
  const off = new Set(p.disabled_tags ?? []);
  const pkgOn = catalog.length ? catalog.filter((c) => !off.has(c.tag)).length : null;
  const excl = p.exclusions?.length ?? 0;
  return (
    <article className="card flex flex-col gap-4 p-5 transition-colors hover:border-border-strong">
      <div className="flex items-start gap-3">
        <div aria-hidden className="flex h-10 w-10 shrink-0 items-center justify-center rounded-[11px] border border-border-strong bg-panel-2 text-accent">
          <ShieldCheck size={20} />
        </div>
        <div className="min-w-0 flex-1">
          <button type="button" onClick={onEdit} className="block max-w-full truncate text-left font-display text-base font-semibold hover:text-accent">
            {p.name}
          </button>
          <div className="mt-0.5 text-xs text-faint">
            {usedBy.length === 0 ? "Not attached to any host" : `Used by ${usedBy.length} ${usedBy.length === 1 ? "host" : "hosts"}`}
          </div>
        </div>
        <span
          className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1 text-xs font-bold ${
            detect ? "bg-warn/10 text-warn" : "bg-danger/10 text-danger"
          }`}
        >
          <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${detect ? "bg-warn" : "bg-danger"}`} />
          {detect ? "Detect only" : "Block"}
        </span>
        <ActionMenu
          label={`Actions for ${p.name}`}
          items={[
            { label: "Edit profile", onSelect: onEdit },
            { label: "Delete", onSelect: onDelete, danger: true },
          ]}
        />
      </div>

      <div>
        <div className="flex items-baseline justify-between text-xs">
          <span className="font-semibold text-dim">Paranoia</span>
          <span className="font-mono text-faint">PL{pl} · {PARANOIA[pl - 1]?.title.split(" · ")[1] ?? ""}</span>
        </div>
        <div className="mt-2 grid grid-cols-4 gap-1.5" role="img" aria-label={`Paranoia level ${pl} of 4`}>
          {[1, 2, 3, 4].map((n) => (
            <span
              key={n}
              className={`h-1.5 rounded-full ${n <= pl ? (n >= 3 ? "bg-warn" : "bg-accent") : "bg-panel-2"}`}
            />
          ))}
        </div>
      </div>

      <dl className="grid grid-cols-3 gap-3 border-t border-border pt-3.5 text-xs">
        <div>
          <dt className="text-faint">Threshold</dt>
          <dd className="mt-0.5 font-mono text-sm text-fg">{p.inbound_threshold || 5}</dd>
        </div>
        <div>
          <dt className="text-faint">Packages</dt>
          <dd className="mt-0.5 font-mono text-sm text-fg">
            {pkgOn === null ? (off.size ? `−${off.size}` : "all") : `${pkgOn}/${catalog.length}`}
          </dd>
        </div>
        <div>
          <dt className="text-faint">Exclusions</dt>
          <dd className="mt-0.5 font-mono text-sm text-fg">{excl}</dd>
        </div>
      </dl>

      {usedBy.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {usedBy.slice(0, 4).map((h) => (
            <span key={h.id} className="rounded-md border border-border-strong bg-panel-2 px-2 py-0.5 font-mono text-[11px] text-dim">
              {h.domain_names[0] ?? h.id.slice(0, 8)}
            </span>
          ))}
          {usedBy.length > 4 && <span className="px-1 text-[11px] text-faint">+{usedBy.length - 4} more</span>}
        </div>
      )}
    </article>
  );
}

function FindingsPanel({
  findings,
  err,
  range,
  setRange,
  host,
  setHost,
  hosts,
  onExclude,
  onRetry,
}: {
  findings: WAFFinding[] | null;
  err: string | null;
  range: "24h" | "7d" | "30d";
  setRange: (r: "24h" | "7d" | "30d") => void;
  host: string;
  setHost: (h: string) => void;
  hosts: Host[];
  onExclude: (f: WAFFinding, scope: "all" | "path" | "input" | "policy") => void;
  onRetry: () => void;
}) {
  return (
    <div className="mt-6">
      <div className="card card-pad">
        <div className="flex flex-wrap items-center gap-3">
          <div>
            <h2 className="section-title">What the rules matched</h2>
            <p className="mt-1 text-xs text-faint">
              Every WAF hit in the request log, grouped by rule. Detect-mode hits show what Block would have stopped. Decide per
              row: turn the rule off for that one input, under that path, or everywhere; each opens the profile with the
              exclusion filled in.
            </p>
          </div>
          <div role="group" aria-label="Time range" className="ml-auto flex gap-0.5 rounded-[11px] border border-border bg-panel p-[3px]">
            {(["24h", "7d", "30d"] as const).map((k) => (
              <button
                key={k}
                type="button"
                aria-pressed={range === k}
                onClick={() => setRange(k)}
                className={`h-[30px] rounded-lg px-3 text-[13px] font-bold transition-colors ${range === k ? "bg-accent text-ink" : "text-dim hover:text-fg"}`}
              >
                {k}
              </button>
            ))}
          </div>
          <select aria-label="Host" className="input w-56 text-sm" value={host} onChange={(e) => setHost(e.target.value)}>
            <option value="">All hosts</option>
            {hosts.filter((h) => h.waf_profile_id).map((h) => (
              <option key={h.id} value={h.id}>
                {(h.domain_names ?? [])[0] || h.id.slice(0, 8)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {err && (
        <div className="mt-4">
          <ErrorState message={err} onRetry={onRetry} />
        </div>
      )}
      <div className="mt-5">
        {findings === null ? (
          <div className="card card-pad">
            <Loading rows={4} label="Loading findings" />
          </div>
        ) : findings.length === 0 ? (
          <Empty
            title="No WAF hits in this range"
            body="Nothing matched a rule. If a profile is in Detect mode and you expected hits, give it traffic for a while and come back."
          />
        ) : (
          <Table
            columns={[
              { label: "Rule" },
              { label: "Hits", align: "right" },
              { label: "Where it matched" },
              { label: "Hosts" },
              { label: "Last seen" },
              { label: <span className="sr-only">Actions</span>, align: "right" },
            ]}
          >
            {findings.map((f) => (
              <tr key={f.rule_id} className="table-row align-top">
                <td className="max-w-[22rem] py-3 pr-5">
                  <div className="flex items-center gap-2">
                    <span className="rounded-md border border-border-strong bg-panel-2 px-1.5 font-mono text-xs">{f.rule_id}</span>
                    {f.paranoia > 1 && <StatusPill tone="warn">PL{f.paranoia}</StatusPill>}
                  </div>
                  <div className="mt-1 text-sm">{f.message || "Unknown rule"}</div>
                  <div className="text-xs text-faint">{f.category}</div>
                </td>
                <td className="whitespace-nowrap py-3 pr-5 text-right">
                  <div className="font-mono text-sm">{fmtInt(f.hits)}</div>
                  <div className="text-xs text-faint">
                    {f.blocked > 0 ? `${fmtInt(f.blocked)} blocked` : "detect only"} · {fmtInt(f.clients)} {f.clients === 1 ? "client" : "clients"}
                  </div>
                </td>
                <td className="max-w-[24rem] py-3 pr-5">
                  <div className="font-mono text-xs">{f.sample_where || "—"}</div>
                  {f.sample_value && (
                    <div className="mt-1 truncate rounded-md border border-border bg-bg px-2 py-1 font-mono text-[11px] text-dim" title={f.sample_value}>
                      {f.sample_value}
                    </div>
                  )}
                  <div className="mt-1 truncate font-mono text-[11px] text-faint" title={f.paths.join("\n")}>
                    {f.paths.slice(0, 2).join("  ")}
                    {f.paths.length > 2 ? `  +${f.paths.length - 2}` : ""}
                  </div>
                </td>
                <td className="max-w-[12rem] py-3 pr-5 text-xs text-dim">
                  {f.hosts.slice(0, 3).join(", ")}
                  {f.hosts.length > 3 ? ` +${f.hosts.length - 3}` : ""}
                </td>
                <td className="whitespace-nowrap py-3 pr-5 text-xs text-dim">{fmtRelative(f.last_seen)}</td>
                <td className="py-3 text-right">
                  <div className="flex flex-col items-end gap-1">
                    {POLICY_RULES[f.rule_id] ? (
                      <button type="button" className="btn btn-secondary btn-sm" onClick={() => onExclude(f, "policy")} title={`Change the profile's ${POLICY_RULES[f.rule_id]}`}>
                        Edit protocol policy
                      </button>
                    ) : (
                      <>
                        {f.sample_where && excludableInput(f.sample_where) && (
                          <button type="button" className="btn btn-secondary btn-sm" onClick={() => onExclude(f, "input")}>
                            Allow this input
                          </button>
                        )}
                        <button type="button" className="btn btn-ghost btn-sm" onClick={() => onExclude(f, "path")} disabled={!f.path}>
                          Off under {f.path ? (f.path.length > 24 ? f.path.slice(0, 24) + "…" : f.path) : "path"}
                        </button>
                        <button type="button" className="btn btn-ghost btn-sm" onClick={() => onExclude(f, "all")}>
                          Off everywhere
                        </button>
                      </>
                    )}
                    <Link href={requestsHref({ rule: f.rule_id, range: range === "24h" ? "24h" : range })} className="btn btn-ghost btn-sm">
                      Show requests
                    </Link>
                  </div>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    </div>
  );
}

const MODES = [
  {
    id: "block" as const,
    title: "Block",
    blurb: "Interrupt matching requests with 403. Use this once the profile is tuned.",
  },
  {
    id: "detect" as const,
    title: "Detect",
    blurb: "Score and log only — never interrupt. Use this to find false positives before blocking.",
  },
];

const PARANOIA = [
  {
    n: 1,
    title: "PL1 · baseline",
    blurb: "Obvious, common attacks. Almost no false positives. Default for most sites.",
  },
  {
    n: 2,
    title: "PL2 · stricter",
    blurb: "Adds tighter SQLi and XSS coverage. Catches more, and some legitimate traffic.",
  },
  {
    n: 3,
    title: "PL3 · aggressive",
    blurb: "Specialized and obfuscated attacks. Regular false positives — plan to tune exclusions.",
  },
  {
    n: 4,
    title: "PL4 · maximum",
    blurb: "Almost every possible attack, and a lot of real users. Crown-jewels only.",
  },
];

// Pill in a one-of-N group (radio semantics).
function Pill({ selected, label, onClick, tone = "accent" }: { selected: boolean; label: string; onClick: () => void; tone?: "accent" | "warn" | "danger" }) {
  const on = { accent: "bg-accent text-ink", warn: "bg-warn text-ink", danger: "bg-danger text-ink" }[tone];
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      tabIndex={selected ? 0 : -1}
      onClick={onClick}
      className={`h-9 rounded-full px-4 text-[13px] font-bold transition-colors ${
        selected ? on : "border border-border-strong text-dim hover:border-border-hover hover:text-fg"
      }`}
    >
      {label}
    </button>
  );
}

// Arrow keys move the selection inside a radiogroup of Pills.
function arrowNav<T>(e: React.KeyboardEvent, items: T[], current: T, set: (v: T) => void) {
  if (!["ArrowRight", "ArrowLeft", "ArrowUp", "ArrowDown"].includes(e.key)) return;
  e.preventDefault();
  const i = items.indexOf(current);
  const n = e.key === "ArrowRight" || e.key === "ArrowDown" ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
  set(items[n]);
  const el = (e.currentTarget as HTMLElement).children[n] as HTMLElement | undefined;
  el?.focus();
}

function WAFDialog({
  profile,
  catalog,
  startDelete = false,
  usedBy,
  prefill,
  rules,
  startPolicyOpen = false,
  onClose,
  onSaved,
}: {
  profile: WAFProfile | null;
  catalog: WAFPackage[];
  startDelete?: boolean;
  usedBy: number;
  // An exclusion to add, from a request's details.
  prefill?: WAFExclusion | null;
  rules?: Map<string, WAFRule>;
  startPolicyOpen?: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = profile !== null;
  const [name, setName] = useState(profile?.name ?? "");
  const [mode, setMode] = useState<"detect" | "block">(profile?.mode === "detect" ? "detect" : "block");
  const [paranoia, setParanoia] = useState(profile?.paranoia || 1);
  const [threshold, setThreshold] = useState(String(profile?.inbound_threshold || 5));
  const [bodyLimitKB, setBodyLimitKB] = useState(String(Math.round((profile?.body_limit_bytes || 1048576) / 1024)));
  // Protocol policy. Empty server lists mean the defaults; the UI always
  // shows and sends the effective lists.
  const [methods, setMethods] = useState<string[]>(profile?.allowed_methods?.length ? profile.allowed_methods : DEFAULT_METHODS);
  const [ctMode, setCtMode] = useState<"default" | "any" | "custom">(
    profile?.any_content_type ? "any" : profile?.allowed_content_types?.length ? "custom" : "default",
  );
  const [ctList, setCtList] = useState((profile?.allowed_content_types ?? []).join("\n"));
  const [restricted, setRestricted] = useState<string[]>(() => {
    const saved = profile?.restricted_headers ?? [];
    if (saved.length === 0) return DEFAULT_RESTRICTED_HEADERS;
    return saved.filter((h) => h !== "x-aegis-none"); // the "restrict nothing" sentinel
  });
  const [policyOpen, setPolicyOpen] = useState(startPolicyOpen);
  const [disabled, setDisabled] = useState<string[]>(profile?.disabled_tags ?? []);
  const [exclusions, setExclusions] = useState<WAFExclusion[]>([
    ...(profile?.exclusions ?? []),
    ...(prefill ? [prefill] : []),
  ]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(!!prefill);
  const [confirmDelete, setConfirmDelete] = useState(startDelete && profile !== null);
  const gid = useId();

  function togglePackage(tag: string) {
    setDisabled((cur) => (cur.includes(tag) ? cur.filter((t) => t !== tag) : [...cur, tag]));
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    const payload: WAFProfileInput = {
      name,
      mode,
      paranoia,
      inbound_threshold: Number(threshold) || 5,
      body_limit_bytes: (Number(bodyLimitKB) || 1024) * 1024,
      allowed_methods: methods,
      allowed_content_types: ctMode === "custom" ? ctList.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean) : [],
      any_content_type: ctMode === "any",
      // An empty list would mean "default" on the server; a profile that
      // restricts nothing sends a name no client uses so the choice sticks.
      restricted_headers: restricted.length ? restricted : ["x-aegis-none"],
      disabled_tags: disabled,
      exclusions: exclusions.filter((x) => x.rule_id.trim()),
    };
    setBusy(true);
    try {
      if (isEdit) await api.updateWAFProfile(profile.id, payload);
      else await api.createWAFProfile(payload);
      onSaved();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  async function onDelete() {
    if (!profile) return;
    setBusy(true);
    setErr(null);
    try {
      await api.deleteWAFProfile(profile.id);
      onSaved();
    } catch (e2) {
      const msg = e2 instanceof ApiError && e2.status === 409
        ? "This profile is attached to hosts. Detach it first."
        : e2 instanceof Error ? e2.message : "Delete failed.";
      setErr(msg);
      setConfirmDelete(false);
    } finally {
      setBusy(false);
    }
  }

  const footer =
    confirmDelete && profile ? (
      <>
        <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => setConfirmDelete(false)}>
          Keep profile
        </button>
        <button type="button" className="btn btn-danger" disabled={busy} onClick={onDelete}>
          <Trash2 size={15} aria-hidden /> {busy ? "Deleting…" : "Delete profile"}
        </button>
      </>
    ) : (
      <>
        {isEdit && (
          <button type="button" className="btn btn-danger mr-auto" disabled={busy} onClick={() => setConfirmDelete(true)}>
            <Trash2 size={15} aria-hidden /> Delete
          </button>
        )}
        <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button type="submit" form="waf-form" className="btn btn-primary" disabled={busy}>
          {busy ? "Saving…" : isEdit ? "Save changes" : "Create profile"}
        </button>
      </>
    );

  return (
    <Dialog
      busy={busy}
      confirmClose={dirty ? "Discard the changes to this profile?" : undefined}
      title={isEdit ? "Edit WAF profile" : "Add WAF profile"}
      description="Policy for Coraza + OWASP CRS. Tune with exclusions; custom SecLang rules are not supported."
      onClose={onClose}
      footer={footer}
    >
        <form id="waf-form" onSubmit={onSubmit} onChange={() => setDirty(true)} className="space-y-5">
          {err && <Notice tone="danger" title={err} />}
          <Field label="Name">
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Default CRS" />
          </Field>

          <div className="space-y-1.5">
            <p id={`${gid}-mode`} className="text-sm text-dim">Mode</p>
            <div
              role="radiogroup"
              aria-labelledby={`${gid}-mode`}
              aria-describedby={`${gid}-mode-h`}
              className="flex flex-wrap gap-2"
              onKeyDown={(e) => arrowNav(e, MODES.map((m) => m.id), mode, setMode)}
            >
              {MODES.map((opt) => (
                <Pill
                  key={opt.id}
                  selected={mode === opt.id}
                  label={opt.title}
                  tone={opt.id === "block" ? "danger" : "warn"}
                  onClick={() => setMode(opt.id)}
                />
              ))}
            </div>
            <p id={`${gid}-mode-h`} className="text-xs text-faint">{MODES.find((m) => m.id === mode)?.blurb}</p>
          </div>

          <div className="space-y-1.5">
            <p id={`${gid}-pl`} className="text-sm text-dim">Paranoia level</p>
            <div
              role="radiogroup"
              aria-labelledby={`${gid}-pl`}
              aria-describedby={`${gid}-pl-h`}
              className="flex flex-wrap gap-2"
              onKeyDown={(e) => arrowNav(e, PARANOIA.map((x) => x.n), paranoia, setParanoia)}
            >
              {PARANOIA.map((opt) => (
                <Pill
                  key={opt.n}
                  selected={paranoia === opt.n}
                  label={opt.title}
                  tone={opt.n >= 3 ? "warn" : "accent"}
                  onClick={() => setParanoia(opt.n)}
                />
              ))}
            </div>
            <p id={`${gid}-pl-h`} className="text-xs text-faint">
              {PARANOIA.find((x) => x.n === paranoia)?.blurb} Higher levels add stricter rules on top of the ones below.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="Inbound anomaly threshold" hint="CRS blocks when the inbound score reaches this value. Default 5.">
              <input
                className="input mono"
                type="number"
                min={1}
                max={100}
                value={threshold}
                onChange={(e) => setThreshold(e.target.value)}
              />
            </Field>
            <Field
              label="Body inspection limit (KB)"
              hint="The first part of each request body the rules read; anything past it is forwarded uninspected, so uploads keep working. 16–65536, default 1024."
            >
              <input
                className="input mono"
                type="number"
                min={16}
                max={65536}
                value={bodyLimitKB}
                onChange={(e) => setBodyLimitKB(e.target.value)}
              />
            </Field>
          </div>

          <div className="rounded-xl border border-border">
            <button
              type="button"
              className="flex w-full items-center justify-between px-4 py-3 text-left"
              aria-expanded={policyOpen}
              onClick={() => setPolicyOpen((v) => !v)}
            >
              <span>
                <span className="text-sm font-semibold">Protocol policy</span>
                <span className="mt-0.5 block text-xs text-faint">
                  {sameSet(methods, DEFAULT_METHODS) ? "REST methods" : `${methods.length} methods`} ·{" "}
                  {ctMode === "any" ? "any content type" : ctMode === "custom" ? "custom content types" : "default content types"} ·{" "}
                  {sameSet(restricted, DEFAULT_RESTRICTED_HEADERS) ? "default header policy" : `${restricted.length} restricted headers`}
                </span>
              </span>
              <span className="text-xs text-accent">{policyOpen ? "Hide" : "Edit"}</span>
            </button>
            {policyOpen && (
              <div className="space-y-5 border-t border-border px-4 py-4">
                <p className="text-xs text-faint">
                  These are CRS rules 911100, 920420 and 920450. Their stock settings are made for a form-posting website and
                  block REST APIs, SDK uploads and WebDAV before any attack rule runs, so Aegis starts wider. Tighten them
                  here per profile.
                </p>
                <div>
                  <div className="flex items-baseline justify-between">
                    <p className="text-sm text-dim">Allowed methods</p>
                    <div className="flex gap-2 text-xs">
                      <button type="button" className="text-accent hover:text-fg" onClick={() => setMethods(DEFAULT_METHODS)}>REST</button>
                      <button type="button" className="text-accent hover:text-fg" onClick={() => setMethods([...new Set([...methods, ...WEBDAV_METHODS])])}>
                        + WebDAV (Nextcloud, CalDAV)
                      </button>
                    </div>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {ALL_METHODS.map((m) => (
                      <Pill
                        key={m}
                        selected={methods.includes(m)}
                        label={m}
                        onClick={() => setMethods((cur) => (cur.includes(m) ? cur.filter((x) => x !== m) : [...cur, m]))}
                      />
                    ))}
                  </div>
                  {methods.length === 0 && <p className="mt-1 text-xs text-danger">Select at least one method.</p>}
                </div>
                <div>
                  <p className="text-sm text-dim">Request content types</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <Pill selected={ctMode === "default"} label="Default list" onClick={() => setCtMode("default")} />
                    <Pill selected={ctMode === "custom"} label="Only these" onClick={() => setCtMode("custom")} />
                    <Pill selected={ctMode === "any"} label="Any" tone="warn" onClick={() => setCtMode("any")} />
                  </div>
                  {ctMode === "default" && <p className="mt-1.5 text-xs text-faint">Allows {DEFAULT_CONTENT_TYPES_SUMMARY}.</p>}
                  {ctMode === "any" && (
                    <p className="mt-1.5 text-xs text-faint">
                      Rule 920420 is turned off. Bodies of unknown types are still forwarded but not parsed by the rules.
                    </p>
                  )}
                  {ctMode === "custom" && (
                    <textarea
                      className="input mono mt-2 min-h-20"
                      placeholder={"application/json\nmultipart/form-data"}
                      value={ctList}
                      onChange={(e) => setCtList(e.target.value)}
                      spellCheck={false}
                    />
                  )}
                </div>
                <div>
                  <p className="text-sm text-dim">Restricted request headers</p>
                  <p className="mt-0.5 text-xs text-faint">A request carrying a ticked header is scored as an attack (rule 920450).</p>
                  <ul className="mt-2 space-y-1.5">
                    {CRS_RESTRICTED_HEADERS.map((h) => (
                      <li key={h.name}>
                        <label className="flex cursor-pointer items-start gap-2.5 text-sm">
                          <input
                            type="checkbox"
                            className="mt-1"
                            checked={restricted.includes(h.name)}
                            onChange={() => setRestricted((cur) => (cur.includes(h.name) ? cur.filter((x) => x !== h.name) : [...cur, h.name]))}
                          />
                          <span>
                            <span className="font-mono text-[13px]">{h.name}</span>
                            <span className="block text-xs text-faint">{h.why}</span>
                          </span>
                        </label>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>

          <div className="space-y-1.5">
            <div className="flex items-baseline justify-between">
              <p id={`${gid}-pkg`} className="text-sm text-dim">Rule packages</p>
              <span className="font-mono text-xs text-faint">
                {catalog.length - catalog.filter((c) => disabled.includes(c.tag)).length}/{catalog.length} on
              </span>
            </div>
            <div role="group" aria-labelledby={`${gid}-pkg`} className="flex flex-wrap gap-2">
              {catalog.map((pkg) => {
                const on = !disabled.includes(pkg.tag);
                return (
                  <button
                    key={pkg.tag}
                    type="button"
                    onClick={() => togglePackage(pkg.tag)}
                    aria-pressed={on}
                    title={pkg.description}
                    className={`inline-flex h-8 items-center gap-1.5 rounded-lg border px-3 text-[13px] font-semibold transition-colors ${
                      on ? "border-accent/40 bg-accent/10 text-accent" : "border-border-strong text-faint line-through decoration-faint/60 hover:text-dim"
                    }`}
                  >
                    {on ? <Check size={13} strokeWidth={3} aria-hidden /> : <X size={13} aria-hidden />}
                    {pkg.name}
                  </button>
                );
              })}
            </div>
            <p className="text-xs text-faint">Switch a package off only when it has no use on these hosts (a PHP pack on a Go API).</p>
          </div>

          <div className="space-y-2">
            <div className="flex items-baseline justify-between">
              <p className="text-sm text-dim">Exclusions</p>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setExclusions((cur) => [...cur, { rule_id: "", path: "", target: "" }])}
              >
                <Plus size={14} strokeWidth={2.4} aria-hidden /> Add exclusion
              </button>
            </div>
            <p className="text-xs text-faint">
              Rule ID, then optionally a path prefix and one input the rule should ignore (for example{" "}
              <span className="font-mono">REQUEST_COOKIES:ph_…_posthog</span>). With an input, the rule keeps checking everything
              else. The proxy log (<span className="font-mono">proxy: waf … at …</span>) names the rule and input to use.
            </p>
            <datalist id={`${gid}-rules`}>
              {rules && [...rules.values()].map((r) => <option key={r.id} value={r.id}>{`${r.message} (${r.category})`}</option>)}
            </datalist>
            {exclusions.length === 0 ? (
              <p className="rounded-xl border border-dashed border-border-strong px-4 py-3 text-sm text-faint">No exclusions.</p>
            ) : (
              <div className="space-y-3">
                {exclusions.map((ex, i) => (
                  <div key={i} className="grid grid-cols-[minmax(0,1fr)_auto] items-end gap-3 sm:grid-cols-[6.5rem_minmax(0,1fr)_minmax(0,1.5fr)_auto]">
                    <div className="space-y-1.5">
                      <label htmlFor={`${gid}-rule-${i}`} className="block text-xs text-faint">Rule ID</label>
                      <input
                        id={`${gid}-rule-${i}`}
                        className="input mono"
                        value={ex.rule_id}
                        placeholder="942100"
                        list={`${gid}-rules`}
                        onChange={(e) => {
                          const v = e.target.value.trim().slice(0, 6);
                          setExclusions((cur) => cur.map((x, j) => (j === i ? { ...x, rule_id: v } : x)));
                        }}
                      />
                      <p className="min-h-4 text-[11px] text-faint">
                        {rules?.get(ex.rule_id)?.message ?? (ex.rule_id.length === 6 ? "Unknown rule id" : "")}
                      </p>
                    </div>
                    <div className="space-y-1.5">
                      <label htmlFor={`${gid}-path-${i}`} className="block text-xs text-faint">Path prefix</label>
                      <input
                        id={`${gid}-path-${i}`}
                        className="input mono"
                        value={ex.path ?? ""}
                        placeholder="/admin"
                        onChange={(e) => {
                          const v = e.target.value;
                          setExclusions((cur) => cur.map((x, j) => (j === i ? { ...x, path: v } : x)));
                        }}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label htmlFor={`${gid}-target-${i}`} className="block text-xs text-faint">Only this input</label>
                      <input
                        id={`${gid}-target-${i}`}
                        className="input mono"
                        value={ex.target ?? ""}
                        placeholder="REQUEST_COOKIES:name"
                        spellCheck={false}
                        onChange={(e) => {
                          const v = e.target.value;
                          setExclusions((cur) => cur.map((x, j) => (j === i ? { ...x, target: v } : x)));
                        }}
                      />
                    </div>
                    <button
                      type="button"
                      className="btn btn-ghost btn-icon"
                      aria-label={`Remove exclusion ${i + 1}`}
                      onClick={() => setExclusions((cur) => cur.filter((_, j) => j !== i))}
                    >
                      <X size={16} aria-hidden />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {confirmDelete && profile && (
            <Notice tone="danger" title={`Delete ${profile.name}?`}>
              {usedBy > 0
                ? `It is attached to ${usedBy} ${usedBy === 1 ? "host" : "hosts"}. Detach it from those hosts first; the server refuses to delete a profile in use.`
                : "No host uses it. This cannot be undone."}
            </Notice>
          )}
        </form>
    </Dialog>
  );
}
