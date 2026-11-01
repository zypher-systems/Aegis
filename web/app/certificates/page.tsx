"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { BadgeCheck, FileBadge, FlaskConical, Plus, Upload, type LucideIcon } from "lucide-react";
import { api, isUnauthorized } from "@/lib/api";
import type { Certificate, CertificateStatus, Host } from "@/lib/types";
import { AppShell } from "@/components/app-shell";
import { daysUntil, fmtDate, fmtDateTime } from "@/lib/format";
import {
  ActionMenu,
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
  usePaged,
  type Tone,
} from "@/components/ui";

type StateFilter = "all" | "valid" | "soon" | "expired";

export default function CertificatesPage() {
  const [certs, setCerts] = useState<Certificate[] | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [mode, setMode] = useState<CertificateStatus | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [requestOpen, setRequestOpen] = useState(false);
  const [q, setQ] = useState("");
  const [state, setState] = useState<StateFilter>("all");

  async function load() {
    try {
      const [list, status, h] = await Promise.all([
        api.certificates(),
        api.certificateStatus(),
        api.hosts().catch(() => [] as Host[]),
      ]);
      setCerts(list);
      setMode(status);
      setHosts(h);
      setErr(null);
    } catch (e) {
      if (isUnauthorized(e)) return;
      setErr(e instanceof Error ? e.message : "Failed to load certificates");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const [busyID, setBusyID] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function onRenew(c: Certificate) {
    setBusyID(c.id);
    setNote(null);
    setErr(null);
    try {
      await api.renewCertificate(c.id);
      setNote(`Renewed ${c.domains[0]}.`);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Renewal failed");
    } finally {
      setBusyID(null);
    }
  }

  async function onAutoRenew(c: Certificate, on: boolean) {
    setErr(null);
    try {
      await api.setCertificateAutoRenew(c.id, on);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Update failed");
    }
  }

  async function onDelete(c: Certificate) {
    if (!confirm(`Delete certificate for ${c.domains.join(", ")}?`)) return;
    try {
      await api.deleteCertificate(c.id);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Delete failed");
    }
  }

  // Which hosts serve each certificate: bound by id, or auto hosts whose
  // first domain this is the newest covering cert for (the config push rule).
  const usage = useMemo(() => {
    const by: Record<string, Host[]> = {};
    for (const h of hosts) {
      if (h.kind === "stream" || h.tls_mode === "none") continue;
      const c = h.cert_id ? (certs ?? []).find((x) => x.id === h.cert_id) : h.tls_mode === "auto" ? coveringCert(h, certs ?? []) : undefined;
      if (c) (by[c.id] ??= []).push(h);
    }
    return by;
  }, [hosts, certs]);

  const counts = useMemo(() => {
    const c: Record<StateFilter, number> = { all: 0, valid: 0, soon: 0, expired: 0 };
    for (const cert of certs ?? []) {
      c.all += 1;
      c[certState(cert)] += 1;
    }
    return c;
  }, [certs]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (certs ?? []).filter((c) => {
      if (state !== "all" && certState(c) !== state) return false;
      if (!needle) return true;
      return c.domains.some((d) => d.toLowerCase().includes(needle)) || c.issuer.toLowerCase().includes(needle);
    });
  }, [certs, q, state]);
  const paged = usePaged(filtered, 25);

  const filters: { id: StateFilter; label: string }[] = [
    { id: "all", label: "All" },
    { id: "valid", label: "Valid" },
    { id: "soon", label: "Expiring soon" },
    { id: "expired", label: "Expired" },
  ];

  return (
    <AppShell>
      <PageHeader
        title="Certificates"
        description="Request Let's Encrypt (HTTP-01 or Cloudflare DNS-01 for wildcards), or upload a PEM. Private keys are never shown."
        actions={
          <>
            <button type="button" className="btn btn-secondary" onClick={() => setUploadOpen(true)}>
              <Upload size={16} aria-hidden /> Upload PEM
            </button>
            <button type="button" className="btn btn-primary" onClick={() => setRequestOpen(true)}>
              <Plus size={16} strokeWidth={2.4} aria-hidden /> Request certificate
            </button>
          </>
        }
      />

      <div className="mt-6 space-y-4">
        {err && <ErrorState message={err} onRetry={load} />}
        {note && (
          <p role="status" className="text-sm text-ok">
            {note}
          </p>
        )}
        {mode?.self_signed && (
          <Notice tone="warn" title="Self-signed mode">
            Requests mint an internal CA certificate, not Let&apos;s Encrypt. To issue public certificates, set{" "}
            <span className="mono">AEGIS_SELFSIGNED=false</span> and <span className="mono">AEGIS_ACME_EMAIL</span>, then
            recreate the API.
          </Notice>
        )}
      </div>

      {certs === null ? (
        <div className="card card-pad mt-6">
          <Loading rows={5} label="Loading certificates" />
        </div>
      ) : certs.length === 0 ? (
        <div className="mt-6">
          <Empty
            title="No certificates yet"
            body={
              mode?.self_signed
                ? "Self-signed mode is on. Request certificate mints an internal CA leaf until you set AEGIS_SELFSIGNED=false."
                : "Request Let's Encrypt first (wildcards need Cloudflare in Settings), then attach the cert on a host."
            }
            action={
              <button type="button" className="btn btn-primary" onClick={() => setRequestOpen(true)}>
                <Plus size={16} strokeWidth={2.4} aria-hidden /> Request certificate
              </button>
            }
          />
        </div>
      ) : (
        <>
          <div className="mt-6 flex flex-wrap items-center gap-2.5">
            <div role="group" aria-label="Filter by state" className="flex flex-wrap gap-2">
              {filters
                .filter((f) => f.id === "all" || counts[f.id] > 0)
                .map((f) => {
                  const on = state === f.id;
                  return (
                    <button
                      key={f.id}
                      type="button"
                      aria-pressed={on}
                      onClick={() => setState(f.id)}
                      className={`h-9 rounded-full px-3.5 text-[13px] font-bold transition-colors ${
                        on ? "bg-accent text-ink" : "border border-border-strong text-dim hover:text-fg"
                      }`}
                    >
                      {f.label} <span className={on ? "" : "text-faint"}>{counts[f.id]}</span>
                    </button>
                  );
                })}
            </div>
            <div className="ml-auto w-full sm:w-72">
              <SearchInput value={q} onChange={setQ} placeholder="Filter by domain or issuer" label="Filter certificates" />
            </div>
          </div>

          <div className="mt-5">
            {filtered.length === 0 ? (
              <Empty body="No certificates match that filter." />
            ) : (
              <div className="card overflow-x-auto">
                <table className="data-table w-full min-w-[52rem] text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-xs font-semibold text-faint">
                      <th scope="col" className="py-3 pr-4 font-semibold">Certificate</th>
                      <th scope="col" className="py-3 pr-4 font-semibold">Issuer</th>
                      <th scope="col" className="py-3 pr-4 font-semibold">Expires</th>
                      <th scope="col" className="py-3 pr-4 font-semibold">Renewal</th>
                      <th scope="col" className="py-3 pr-4 font-semibold">Used by</th>
                      <th scope="col" className="py-3">
                        <span className="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {paged.pageItems.map((c) => {
                      const used = usage[c.id] ?? [];
                      return (
                        <tr key={c.id} className="table-row">
                          <td className="py-3 pr-4">
                            <div className="flex items-center gap-3">
                              <div
                                aria-hidden
                                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[10px] border border-border-strong bg-panel-2 text-dim"
                              >
                                <FileBadge size={17} />
                              </div>
                              <div className="min-w-0">
                                <div className="max-w-[22rem] truncate font-display text-[15px] font-semibold">
                                  {c.domains[0] ?? "(no names)"}
                                  {c.domains.length > 1 && (
                                    <span className="ml-1.5 text-xs font-normal text-faint">+{c.domains.length - 1}</span>
                                  )}
                                </div>
                                {c.domains.length > 1 && (
                                  <div className="max-w-[22rem] truncate font-mono text-xs text-faint" title={c.domains.join(", ")}>
                                    {c.domains.slice(1).join(", ")}
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                          <td className="py-3 pr-4">
                            <IssuerLabel issuer={c.issuer} />
                          </td>
                          <td className="py-3 pr-4">
                            <Expiry value={c.expires_at} />
                          </td>
                          <td className="py-3 pr-4">
                            <RenewalCell c={c} selfSigned={mode?.self_signed === true} busy={busyID === c.id} />
                          </td>
                          <td className="py-3 pr-4">
                            {used.length === 0 ? (
                              <span className="text-xs text-faint">Not in use</span>
                            ) : (
                              <span className="text-xs text-dim" title={used.map((h) => h.domain_names[0]).join(", ")}>
                                <span className="font-mono text-fg">{used.length}</span> {used.length === 1 ? "host" : "hosts"}
                                <span className="block max-w-[14rem] truncate text-faint">{used.map((h) => h.domain_names[0]).join(", ")}</span>
                              </span>
                            )}
                          </td>
                          <td className="py-3 text-right">
                            <div className="flex justify-end">
                              <ActionMenu
                                label={`Actions for ${c.domains[0] ?? "certificate"}`}
                                items={[
                                  ...(c.issuer === "letsencrypt" && mode?.self_signed !== true
                                    ? [
                                        { label: busyID === c.id ? "Renewing…" : "Renew now", onSelect: () => onRenew(c) },
                                        {
                                          label: c.auto_renew === false ? "Turn auto-renew on" : "Turn auto-renew off",
                                          onSelect: () => onAutoRenew(c, c.auto_renew === false),
                                        },
                                      ]
                                    : []),
                                  { label: "Download certificate (PEM)", onSelect: () => window.open(api.certificatePEMURL(c.id), "_blank") },
                                  { label: "Delete certificate", danger: true, onSelect: () => onDelete(c) },
                                ]}
                              />
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <Pager {...paged} noun={filtered.length === 1 ? "certificate" : "certificates"} />
          </div>
        </>
      )}

      {requestOpen && (
        <RequestDialog
          onClose={() => setRequestOpen(false)}
          onSaved={async () => {
            setRequestOpen(false);
            await load();
          }}
          selfSigned={mode?.self_signed === true}
        />
      )}
      {uploadOpen && (
        <UploadDialog
          onClose={() => setUploadOpen(false)}
          onSaved={async () => {
            setUploadOpen(false);
            await load();
          }}
        />
      )}
    </AppShell>
  );
}

// What will happen to this certificate before it expires.
function RenewalCell({ c, selfSigned, busy }: { c: Certificate; selfSigned: boolean; busy: boolean }) {
  const days = daysUntil(c.expires_at);
  if (busy) return <span className="text-xs text-accent">Renewing…</span>;
  if (c.issuer === "custom") {
    return <span className="text-xs text-dim">Uploaded: re-upload before expiry</span>;
  }
  if (c.issuer === "selfsigned" || selfSigned) {
    return <span className="text-xs text-dim">Self-signed: not renewed</span>;
  }
  if (c.auto_renew === false) {
    return <span className="text-xs text-warn">Auto-renew off</span>;
  }
  if (c.renewal?.failing) {
    const next = c.renewal.next_attempt ? fmtDateTime(c.renewal.next_attempt) : "soon";
    return (
      <span className="text-xs text-danger" title="See the Overview notice for the error">
        Renewal failing ({c.renewal.fails ?? 1}×), next try {next}
      </span>
    );
  }
  if (days !== null && days <= 30) {
    return <span className="text-xs text-accent">Renews at the next hourly check</span>;
  }
  return <span className="text-xs text-dim">Auto-renews {days !== null ? `in ${days - 30} days` : "before expiry"}</span>;
}

function certState(c: Certificate): Exclude<StateFilter, "all"> {
  const d = daysUntil(c.expires_at);
  if (d === null) return "valid";
  if (d < 0) return "expired";
  if (d <= 14) return "soon";
  return "valid";
}

// An auto host without a bound cert uses the newest cert that covers its
// first domain. Mirrors the Hosts page and the config push.
function coveringCert(h: Host, certs: Certificate[]) {
  const d = h.domain_names[0];
  if (!d) return undefined;
  const covers = (pattern: string) =>
    pattern === d || (pattern.startsWith("*.") && d.endsWith(pattern.slice(1)) && d.split(".").length === pattern.split(".").length);
  return certs
    .filter((c) => (c.domains ?? []).some(covers))
    .sort((a, b) => (a.expires_at < b.expires_at ? 1 : -1))[0];
}

function IssuerLabel({ issuer }: { issuer: string }) {
  const [Icon, label, color]: [LucideIcon, string, string] =
    issuer === "letsencrypt"
      ? [BadgeCheck, "Let’s Encrypt", "text-accent"]
      : issuer === "selfsigned"
        ? [FlaskConical, "Self-signed", "text-warn"]
        : [FileBadge, "Custom upload", "text-dim"];
  return (
    <span className="inline-flex items-center gap-2 text-sm text-dim">
      <Icon size={15} className={color} aria-hidden /> {label}
    </span>
  );
}

// Days-left meter against a 90-day window (the Let's Encrypt lifetime).
function Expiry({ value }: { value: string }) {
  const days = daysUntil(value);
  if (days === null) return <span className="text-dim">{value || "—"}</span>;
  const tone: Tone = days < 0 ? "danger" : days <= 14 ? "warn" : "ok";
  const bar = { ok: "bg-ok", warn: "bg-warn", danger: "bg-danger", neutral: "bg-faint", accent: "bg-accent" }[tone];
  const pct = days < 0 ? 100 : Math.max(4, Math.min(100, (days / 90) * 100));
  return (
    <div className="w-56">
      <div className="flex items-center justify-between gap-2">
        <span className="whitespace-nowrap font-mono text-xs text-dim">{fmtDate(value)}</span>
        <StatusPill tone={tone}>{days < 0 ? `Expired ${-days}d ago` : `${days}d left`}</StatusPill>
      </div>
      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-panel-2" aria-hidden>
        <div className={`h-full rounded-full ${bar}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function RequestDialog({
  onClose,
  onSaved,
  selfSigned,
}: {
  onClose: () => void;
  onSaved: () => void;
  selfSigned: boolean;
}) {
  const [domains, setDomains] = useState("");
  const [cf, setCf] = useState<{ configured: boolean } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.dnsCloudflareStatus().then(setCf).catch(() => setCf({ configured: false }));
  }, []);

  const names = domains.split(",").map((s) => s.trim()).filter(Boolean);
  const needsDNS = names.some((d) => d.startsWith("*."));

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    if (names.length === 0) return setErr("At least one domain is required.");
    if (needsDNS && cf && !cf.configured) {
      return setErr("Wildcards need a Cloudflare API token on Settings.");
    }
    setBusy(true);
    try {
      await api.issueCertificate(names);
      onSaved();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      title="Request certificate"
      description={
        selfSigned
          ? "Self-signed mode is on. Request will mint an internal CA leaf. Turn off AEGIS_SELFSIGNED and set AEGIS_ACME_EMAIL for Let's Encrypt."
          : "Let's Encrypt via ACME. Exact names use HTTP-01 (the name must reach this proxy on 80). Wildcards use Cloudflare DNS-01 and often take 1–2 minutes — leave this open. Request before creating hosts, then attach with Existing cert or Auto."
      }
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="cert-request" className="btn btn-primary" disabled={busy}>
            {busy ? "Requesting…" : "Request"}
          </button>
        </>
      }
    >
      <form id="cert-request" onSubmit={onSubmit} className="space-y-3">
        {err && <p className="text-sm text-danger">{err}</p>}
        <Field
          label="Domain names"
          hint={
            <>
              Comma-separated. Include the apex and the wildcard — <span className="mono">*.example.com</span> does not
              cover <span className="mono">example.com</span>.
            </>
          }
        >
          <input
            className="input mono"
            required
            autoFocus
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
            placeholder="example.com, *.example.com"
          />
        </Field>
        <p className={`text-xs ${needsDNS && cf && !cf.configured ? "text-warn" : "text-faint"}`}>
          Cloudflare DNS-01: {cf?.configured ? "token configured" : "not configured (Settings)"}
        </p>
      </form>
    </Dialog>
  );
}

function UploadDialog({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [chain, setChain] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await api.uploadCertificate(cert, key, chain);
      onSaved();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      title="Upload certificate"
      description="PEM leaf + private key. Optional chain. No auto-renew — re-upload before expiry."
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="cert-upload" className="btn btn-primary" disabled={busy}>
            {busy ? "Uploading…" : "Upload"}
          </button>
        </>
      }
    >
      <form id="cert-upload" onSubmit={onSubmit} className="space-y-3">
        {err && <p className="text-sm text-danger">{err}</p>}
        <Field label="Certificate">
          <textarea
            className="input mono h-28 text-xs"
            required
            placeholder="-----BEGIN CERTIFICATE-----"
            value={cert}
            onChange={(e) => setCert(e.target.value)}
          />
        </Field>
        <Field label="Private key">
          <textarea
            className="input mono h-28 text-xs"
            required
            placeholder="-----BEGIN PRIVATE KEY-----"
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
        </Field>
        <Field label="Chain (optional)">
          <textarea
            className="input mono h-20"
            placeholder="-----BEGIN CERTIFICATE-----"
            value={chain}
            onChange={(e) => setChain(e.target.value)}
          />
        </Field>
      </form>
    </Dialog>
  );
}
