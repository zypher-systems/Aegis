"use client";

import { FormEvent, ReactNode, useEffect, useState } from "react";
import {
  Bell,
  CheckCircle2,
  Cloud,
  Flame,
  Globe2,
  KeyRound,
  Lock,
  Network,
  Plus,
  ScrollText,
  ShieldCheck,
  Ticket,
  Users,
  type LucideIcon,
} from "lucide-react";
import { api, isUnauthorized } from "@/lib/api";
import type { AuditEvent, CrowdSecStatus, EnrollToken, EnrollTokenStatus, User } from "@/lib/types";
import { AppShell } from "@/components/app-shell";
import { useAuth } from "@/lib/auth";
import { fmtDate, fmtDateTime } from "@/lib/format";
import {
  ActionMenu,
  Dialog,
  Empty,
  Field,
  Loading,
  PageHeader,
  Pager,
  Section,
  StatusPill,
  Switch,
  TabPanel,
  Tabs,
  Table,
  useHashTab,
  usePaged,
  type Tone,
} from "@/components/ui";

const TAB_IDS = ["account", "team", "edge", "security"] as const;
type TabId = (typeof TAB_IDS)[number];
// Older links (and the Overview posture checks) point at section names.
const TAB_ALIASES: Record<string, TabId> = {
  crowdsec: "security",
  geoip: "security",
  users: "team",
  audit: "team",
  enrollment: "edge",
  "trusted-proxies": "edge",
  cloudflare: "edge",
  password: "account",
  license: "security",
};

// Card title with a Lucide icon in a tinted tile.
function CardTitle({ icon: Icon, children }: { icon: LucideIcon; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-3">
      <span aria-hidden className="flex h-8 w-8 items-center justify-center rounded-[9px] bg-accent/10 text-accent">
        <Icon size={17} strokeWidth={2} />
      </span>
      {children}
    </span>
  );
}

export default function SettingsPage() {
  const { user: me } = useAuth();
  const [tab, setTab] = useHashTab<TabId>(TAB_IDS, "account");
  const [enrollStatus, setEnrollStatus] = useState<EnrollTokenStatus | null>(null);
  const [enrollTokens, setEnrollTokens] = useState<EnrollToken[]>([]);
  const [token, setToken] = useState<string | null>(null);
  const [tokenLabel, setTokenLabel] = useState("");
  const [tokenTTL, setTokenTTL] = useState(60);
  const [tokenUses, setTokenUses] = useState(1);
  const [cfConfigured, setCfConfigured] = useState<boolean | null>(null);
  const [cfToken, setCfToken] = useState("");
  const [cs, setCs] = useState<CrowdSecStatus | null>(null);
  const [fwBusy, setFwBusy] = useState(false);
  const [geoip, setGeoip] = useState<{ configured: boolean; path: string } | null>(null);
  const [trustedCIDRs, setTrustedCIDRs] = useState("");
  const [tpBusy, setTpBusy] = useState(false);
  const [renewDays, setRenewDays] = useState<string>("");
  const [renewBusy, setRenewBusy] = useState(false);
  const [alertHint, setAlertHint] = useState<string | null>(null); // null = loading, "" = off
  const [alertURL, setAlertURL] = useState("");
  const [alertBusy, setAlertBusy] = useState<"" | "save" | "test">("");
  const [alertMsg, setAlertMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [users, setUsers] = useState<User[] | null>(null);
  const [audit, setAudit] = useState<AuditEvent[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [cfBusy, setCfBusy] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const auditPage = usePaged(audit ?? [], 25);
  const [openAudit, setOpenAudit] = useState<AuditEvent | null>(null);

  // Map section-name hashes (#crowdsec, #users, …) onto their tab.
  useEffect(() => {
    const resolve = () => {
      const alias = TAB_ALIASES[window.location.hash.slice(1)];
      if (alias) setTab(alias);
    };
    resolve();
    window.addEventListener("hashchange", resolve);
    return () => window.removeEventListener("hashchange", resolve);
  }, [setTab]);

  async function load() {
    try {
      const [enroll, cf, u, ev, cs, geo, tp, al, certCfg] = await Promise.all([
        api.enrollTokenStatus(),
        api.dnsCloudflareStatus(),
        api.users(),
        api.audit(50),
        api.crowdsecStatus(),
        api.geoipStatus(),
        api.trustedProxyStatus(),
        api.alertsStatus().catch(() => ({ configured: false, hint: "" })),
        api.certSettings().catch(() => ({ renew_before_days: 30 })),
      ]);
      setEnrollStatus(enroll);
      setEnrollTokens(await api.enrollTokens().catch(() => []));
      setCfConfigured(cf.configured);
      setUsers(u);
      setAudit(ev);
      setCs(cs);
      setGeoip(geo);
      setTrustedCIDRs((tp.cidrs ?? []).join("\n"));
      setAlertHint(al.configured ? al.hint : "");
        setRenewDays(String(certCfg.renew_before_days));
    } catch (e) {
      if (isUnauthorized(e)) return;
      setErr(e instanceof Error ? e.message : "Failed to load settings");
    }
  }

  useEffect(() => { load(); }, []);


  async function mintToken() {
    setBusy(true);
    setErr(null);
    try {
      const out = await api.createEnrollToken({ label: tokenLabel.trim(), ttl_minutes: tokenTTL, uses: tokenUses });
      setToken(out.token);
      setTokenLabel("");
      setEnrollTokens(await api.enrollTokens());
      setEnrollStatus(await api.enrollTokenStatus());
      setAudit(await api.audit(50));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not generate a token");
    } finally {
      setBusy(false);
    }
  }

  async function revokeToken(t: EnrollToken) {
    if (!window.confirm(`Revoke enrolment token${t.label ? ` "${t.label}"` : ""}? A node that has not enrolled yet with it will be refused.`)) return;
    try {
      await api.deleteEnrollToken(t.id);
      setEnrollTokens((cur) => cur.filter((x) => x.id !== t.id));
      setEnrollStatus(await api.enrollTokenStatus());
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Revoke failed");
    }
  }

  async function onDeleteUser(u: User) {
    if (!confirm(`Delete admin ${u.email}? Their sessions will stop working.`)) return;
    setErr(null);
    try {
      await api.deleteUser(u.id);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Delete failed");
    }
  }

  return (
    <AppShell>
      <PageHeader
        title="Settings"
        description="Your account, the admin team and audit trail, edge enrollment, and security integrations."
      />
      {err && <p className="mt-4 text-sm text-danger">{err}</p>}

      <div className="mt-6">
        <Tabs
          label="Settings sections"
          value={tab}
          onChange={setTab}
          items={[
            { id: "account", label: "Account" },
            { id: "team", label: "Team & audit", count: users?.length },
            { id: "edge", label: "Edge" },
            { id: "security", label: "Security" },
          ]}
        />
      </div>

      <div className="mt-6">
        <TabPanel id="account" active={tab === "account"}>
          <PasswordChangeForm email={me?.email} />
        </TabPanel>

        <TabPanel id="team" active={tab === "team"}>
          <div className="flex flex-col gap-5">
            <Section
              card
              title={<CardTitle icon={Users}>Users</CardTitle>}
              description="Every account is an admin. Creating one requires a password. The last admin cannot be deleted."
              actions={
                <button className="btn btn-primary btn-sm" onClick={() => { setEditing(null); setUserOpen(true); }}>
                  <Plus size={15} strokeWidth={2.4} aria-hidden /> Add admin
                </button>
              }
            >
              {users === null ? (
                <Loading rows={2} label="Loading users" />
              ) : (
                <Table bare columns={[{ label: "Name" }, { label: "Email" }, { label: "Role" }, { label: "", align: "right" }]}>
                  {users.map((u) => (
                    <tr key={u.id} className="table-row">
                      <td className="py-3 pr-5">
                        <span className="inline-flex items-center gap-3">
                          <span
                            aria-hidden
                            className="flex h-8 w-8 items-center justify-center rounded-full border border-border-strong bg-panel-2 text-xs font-bold text-dim"
                          >
                            {initials(u.name || u.email)}
                          </span>
                          <span className="font-semibold text-fg">{u.name || "—"}</span>
                          {me?.id === u.id && <span className="text-xs text-faint">you</span>}
                        </span>
                      </td>
                      <td className="py-3 pr-5 mono text-dim">{u.email}</td>
                      <td className="py-3 pr-5">
                        <StatusPill tone="accent">{u.role}</StatusPill>
                      </td>
                      <td className="py-3 text-right">
                        <div className="flex justify-end">
                          <ActionMenu
                            label={`Actions for ${u.email}`}
                            items={[
                              { label: "Edit admin", onSelect: () => { setEditing(u); setUserOpen(true); } },
                              { label: "Delete admin", danger: true, onSelect: () => onDeleteUser(u) },
                            ]}
                          />
                        </div>
                      </td>
                    </tr>
                  ))}
                </Table>
              )}
            </Section>

            <Section
              card
              title={<CardTitle icon={ScrollText}>Audit log</CardTitle>}
              description="Who changed hosts, certs, access lists, users, and settings. Secrets are never stored."
            >
              {audit === null ? (
                <Loading rows={4} label="Loading audit" />
              ) : audit.length === 0 ? (
                <Empty body="No events yet." />
              ) : (
                <>
                  <Table bare columns={[{ label: "When" }, { label: "Who" }, { label: "Action" }, { label: "Resource" }]}>
                    {auditPage.pageItems.map((e) => (
                      <tr key={e.id} className="table-row cursor-pointer" onClick={() => setOpenAudit(e)}>
                        <td className="whitespace-nowrap py-2.5 pr-5 mono text-xs text-dim">
                          <button
                            type="button"
                            className="hover:text-fg"
                            aria-label={`Details of ${e.action} ${e.resource_type} at ${fmtDateTime(e.at)}`}
                            onClick={(ev) => {
                              ev.stopPropagation();
                              setOpenAudit(e);
                            }}
                          >
                            {fmtDateTime(e.at)}
                          </button>
                        </td>
                        <td className="py-2.5 pr-5 mono text-xs text-dim">{e.actor_email || "—"}</td>
                        <td className="py-2.5 pr-5">
                          <StatusPill tone={actionTone(e.action)}>{e.action}</StatusPill>
                        </td>
                        <td className="py-2.5 text-dim">
                          <span className="text-faint">{e.resource_type}</span> <AuditResource e={e} />
                        </td>
                      </tr>
                    ))}
                  </Table>
                  <Pager {...auditPage} noun="events" />
                </>
              )}
            </Section>
          </div>
        </TabPanel>

        <TabPanel id="edge" active={tab === "edge"}>
          <div className="grid gap-5 xl:grid-cols-2">
            <Section
              card
              title={<CardTitle icon={Ticket}>Enrolment tokens</CardTitle>}
              description={
                <>
                  A new proxy node presents a token once. Tokens are short-lived and single-use by default. The
                  value in <span className="mono">.env</span> only enrols the very first node; after that it is
                  ignored, so a leaked env file cannot add a rogue edge.
                </>
              }
            >
              <div className="flex flex-wrap items-center gap-3">
                {enrollStatus === null ? (
                  <StatusPill tone="neutral">Checking</StatusPill>
                ) : enrollStatus.bootstrap_accepted ? (
                  <StatusPill tone="warn">Env bootstrap token accepted (no nodes yet)</StatusPill>
                ) : (
                  <StatusPill tone="ok">Env bootstrap token disabled</StatusPill>
                )}
                {enrollStatus && (
                  <span className="text-xs text-faint">
                    {enrollStatus.nodes} node{enrollStatus.nodes === 1 ? "" : "s"} enrolled · {enrollStatus.live_tokens} live token
                    {enrollStatus.live_tokens === 1 ? "" : "s"}
                  </span>
                )}
              </div>
              <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_auto_auto]">
                <Field label="Label" hint="What or where this node is">
                  <input className="input" value={tokenLabel} onChange={(e) => setTokenLabel(e.target.value)} placeholder="edge-2 at the office" />
                </Field>
                <Field label="Valid for">
                  <select className="input" value={tokenTTL} onChange={(e) => setTokenTTL(Number(e.target.value))}>
                    <option value={15}>15 minutes</option>
                    <option value={60}>1 hour</option>
                    <option value={240}>4 hours</option>
                    <option value={1440}>24 hours</option>
                  </select>
                </Field>
                <Field label="Uses">
                  <select className="input" value={tokenUses} onChange={(e) => setTokenUses(Number(e.target.value))}>
                    {[1, 2, 3, 5, 10].map((n) => (
                      <option key={n} value={n}>
                        {n}
                      </option>
                    ))}
                  </select>
                </Field>
              </div>
              <button className="btn btn-primary mt-3" disabled={busy} onClick={mintToken}>
                {busy ? "Generating…" : "Generate enrolment token"}
              </button>
              {token && (
                <div className="mt-4 rounded-xl border border-accent/30 bg-accent/5 p-3">
                  <div className="text-xs font-semibold text-accent">Shown once. Copy it now.</div>
                  <div className="mono mt-1 break-all text-sm">{token}</div>
                  <div className="mt-1 text-xs text-faint">
                    Pass it as <span className="mono">AEGIS_ENROLL_TOKEN</span> when starting the new proxy.
                  </div>
                </div>
              )}
              {enrollTokens.length > 0 && (
                <ul className="mt-4 divide-y divide-line text-sm">
                  {enrollTokens.map((t) => (
                    <li key={t.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                      <div>
                        <div className="font-medium">{t.label || "Unlabelled token"}</div>
                        <div className="text-xs text-faint">
                          {t.uses_left} use{t.uses_left === 1 ? "" : "s"} left · expires {fmtDateTime(t.expires_at)}
                          {t.created_by ? ` · by ${t.created_by}` : ""}
                        </div>
                      </div>
                      <button type="button" className="btn btn-ghost btn-sm text-danger" onClick={() => revokeToken(t)}>
                        Revoke
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Section>

            <Section
              card
              title={<CardTitle icon={Cloud}>Cloudflare DNS-01</CardTitle>}
              description={
                <>
                  Required to issue <span className="mono">*.example.com</span> via Let&apos;s Encrypt.
                  Token is encrypted at rest. The value is write-only.
                </>
              }
            >
              <div className="flex flex-wrap items-center gap-3">
                {cfConfigured === null ? (
                  <StatusPill tone="neutral">Checking</StatusPill>
                ) : cfConfigured ? (
                  <StatusPill tone="ok">Token configured</StatusPill>
                ) : (
                  <StatusPill tone="neutral">Not configured</StatusPill>
                )}
                {cfConfigured === false && (
                  <span className="text-xs text-faint">
                    Env <span className="mono">AEGIS_CF_API_TOKEN</span> can bootstrap.
                  </span>
                )}
              </div>
              <div className="mt-4 flex max-w-xl flex-col gap-3 sm:flex-row sm:items-end">
                <Field label="API token" className="flex-1">
                  <input
                    className="input mono"
                    type="password"
                    autoComplete="off"
                    placeholder="Cloudflare API token"
                    value={cfToken}
                    onChange={(e) => setCfToken(e.target.value)}
                  />
                </Field>
                <button
                  className="btn btn-primary"
                  disabled={cfBusy || !cfToken}
                  onClick={async () => {
                    setCfBusy(true);
                    setErr(null);
                    try {
                      await api.putDNSCloudflare(cfToken);
                      setCfToken("");
                      setCfConfigured(true);
                      setAudit(await api.audit(50));
                    } catch (e) {
                      setErr(e instanceof Error ? e.message : "Save failed");
                    } finally {
                      setCfBusy(false);
                    }
                  }}
                >
                  {cfBusy ? "Saving…" : "Save token"}
                </button>
              </div>
            </Section>

            <div className="xl:col-span-2">
              <Section
                card
                title={<CardTitle icon={Network}>Trusted proxies</CardTitle>}
                description={
                  <>
                    CIDRs of hops whose <span className="mono">X-Forwarded-For</span> we honour.
                    Empty (the default) uses the connecting address — correct when Aegis is the edge.
                    One CIDR or IP per line. Also settable as <span className="mono">AEGIS_TRUSTED_PROXY_CIDRS</span>; Settings wins once saved.
                  </>
                }
              >
                <div className="max-w-xl">
                  <Field label="Trusted CIDRs">
                    <textarea
                      className="input mono min-h-24"
                      placeholder={"10.0.0.0/8\n172.16.0.0/12"}
                      value={trustedCIDRs}
                      onChange={(e) => setTrustedCIDRs(e.target.value)}
                    />
                  </Field>
                  <button
                    className="btn btn-primary mt-4"
                    disabled={tpBusy}
                    onClick={async () => {
                      setTpBusy(true);
                      setErr(null);
                      try {
                        const cidrs = trustedCIDRs.split(/\s+/).map((s) => s.trim()).filter(Boolean);
                        const out = await api.putTrustedProxy(cidrs);
                        setTrustedCIDRs((out.cidrs ?? []).join("\n"));
                        setAudit(await api.audit(50));
                      } catch (e) {
                        setErr(e instanceof Error ? e.message : "Save failed");
                      } finally {
                        setTpBusy(false);
                      }
                    }}
                  >
                    {tpBusy ? "Saving…" : "Save trusted proxies"}
                  </button>
                </div>
              </Section>

              <Section
                card
                title={<CardTitle icon={Bell}>Alerts</CardTitle>}
                description={
                  <>
                    A webhook that is called when something needs a person: a certificate that will not renew, a node
                    offline or about to lose its certificate, a WAF profile that failed to compile,
                    CrowdSec unreachable. One call when it starts, one when it resolves. Slack and Discord incoming
                    webhooks work as-is; anything else gets JSON with <span className="mono">title</span>,{" "}
                    <span className="mono">detail</span>, <span className="mono">kind</span> and{" "}
                    <span className="mono">status</span>.
                  </>
                }
              >
                <div className="max-w-xl">
                  <div className="mb-3 flex flex-wrap items-center gap-3">
                    {alertHint === null ? (
                      <StatusPill tone="neutral">Checking</StatusPill>
                    ) : alertHint ? (
                      <StatusPill tone="ok">Sending to {alertHint}</StatusPill>
                    ) : (
                      <StatusPill tone="warn">Off: notices only show on the Overview</StatusPill>
                    )}
                  </div>
                  <Field label="Webhook URL" hint="Leave empty and save to turn alerts off.">
                    <input
                      className="input mono"
                      type="url"
                      placeholder="https://hooks.slack.com/services/…"
                      value={alertURL}
                      onChange={(e) => setAlertURL(e.target.value)}
                      spellCheck={false}
                    />
                  </Field>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <button
                      className="btn btn-primary"
                      disabled={alertBusy !== ""}
                      onClick={async () => {
                        setAlertBusy("save");
                        setAlertMsg(null);
                        try {
                          const out = await api.putAlerts(alertURL.trim());
                          setAlertHint(out.configured ? out.hint : "");
                          setAlertURL("");
                          setAlertMsg({ ok: true, text: out.configured ? "Saved. Send a test to confirm delivery." : "Alerts are off." });
                          setAudit(await api.audit(50));
                        } catch (e) {
                          setAlertMsg({ ok: false, text: e instanceof Error ? e.message : "Save failed" });
                        } finally {
                          setAlertBusy("");
                        }
                      }}
                    >
                      {alertBusy === "save" ? "Saving…" : "Save webhook"}
                    </button>
                    <button
                      className="btn btn-secondary"
                      disabled={alertBusy !== "" || !alertHint}
                      onClick={async () => {
                        setAlertBusy("test");
                        setAlertMsg(null);
                        try {
                          await api.testAlerts();
                          setAlertMsg({ ok: true, text: "Test delivered." });
                        } catch (e) {
                          setAlertMsg({ ok: false, text: e instanceof Error ? e.message : "Test failed" });
                        } finally {
                          setAlertBusy("");
                        }
                      }}
                    >
                      {alertBusy === "test" ? "Sending…" : "Send test"}
                    </button>
                  </div>
                  {alertMsg && (
                    <p role="status" className={`mt-3 text-sm ${alertMsg.ok ? "text-ok" : "text-danger"}`}>
                      {alertMsg.text}
                    </p>
                  )}
                </div>
              </Section>

              <Section
                card
                title={<CardTitle icon={ShieldCheck}>Certificate renewal</CardTitle>}
                description="Let's Encrypt certificates renew in place this many days before they expire (hourly check). Uploaded certificates are never renewed; a notice and alert fire 14 days before one expires."
              >
                <div className="flex max-w-md flex-wrap items-end gap-3">
                  <Field label="Renew before expiry (days)" hint="7–60. Let's Encrypt recommends 30 for 90-day certificates.">
                    <input className="input mono w-32" inputMode="numeric" value={renewDays} onChange={(e) => setRenewDays(e.target.value)} />
                  </Field>
                  <button
                    className="btn btn-primary"
                    disabled={renewBusy}
                    onClick={async () => {
                      setRenewBusy(true);
                      setErr(null);
                      try {
                        const out = await api.putCertSettings(parseInt(renewDays, 10) || 30);
                        setRenewDays(String(out.renew_before_days));
                        setAudit(await api.audit(50));
                      } catch (e) {
                        setErr(e instanceof Error ? e.message : "Save failed");
                      } finally {
                        setRenewBusy(false);
                      }
                    }}
                  >
                    {renewBusy ? "Saving…" : "Save"}
                  </button>
                </div>
              </Section>
            </div>
          </div>
        </TabPanel>

        <TabPanel id="security" active={tab === "security"}>
          <div className="grid gap-5 xl:grid-cols-2">
            <div id="crowdsec">
              <Section
                card
                className="h-full"
                title={<CardTitle icon={Flame}>CrowdSec</CardTitle>}
                description="Community lists and manual bans land on the host firewall. Local log scenarios land on L7 for each host with CrowdSec on. RFC1918 and loopback stay allowlisted."
              >
                <div className="flex flex-wrap items-center gap-3">
                  {cs === null ? (
                    <StatusPill tone="neutral">Checking</StatusPill>
                  ) : !cs.configured ? (
                    <StatusPill tone="warn">Not seeded</StatusPill>
                  ) : cs.lapi_ok ? (
                    <StatusPill tone="ok">LAPI reachable</StatusPill>
                  ) : (
                    <StatusPill tone="danger">LAPI not reachable</StatusPill>
                  )}
                  <span className="mono text-xs text-faint">
                    {cs === null
                      ? ""
                      : cs.configured
                        ? cs.url || "LAPI"
                        : "Set CROWDSEC_BOUNCER_KEY in .env and restart the API."}
                  </span>
                </div>
                {cs && (
                  <div className="mt-4 max-w-xl rounded-xl border border-border bg-bg px-4 py-1">
                    <Switch
                      label={fwBusy ? "Host firewall …" : "Host firewall"}
                      checked={!!cs.firewall_enabled}
                      disabled={fwBusy || !cs.firewall_control}
                      locked={
                        !cs.firewall_control
                          ? "Control volume is not mounted; the firewall container stays at its last state."
                          : undefined
                      }
                      description="Optional whole-box filter (host network + NET_ADMIN). Off idles the bouncer. L7 CrowdSec and Analytics bans stay available."
                      onChange={async (next) => {
                        setFwBusy(true);
                        setErr(null);
                        try {
                          const out = await api.putCrowdsecFirewall(next);
                          setCs({ ...cs, firewall_enabled: out.firewall_enabled, firewall_control: out.firewall_control });
                          setAudit(await api.audit(50));
                        } catch (e) {
                          setErr(e instanceof Error ? e.message : "Firewall toggle failed");
                        } finally {
                          setFwBusy(false);
                        }
                      }}
                    />
                  </div>
                )}
              </Section>
            </div>

            <div id="geoip">
              <Section
                card
                className="h-full"
                title={<CardTitle icon={Globe2}>GeoIP</CardTitle>}
                description={
                  <>
                    Optional country allow/deny. Images include a DB-IP Country Lite
                    database. Override <span className="mono">AEGIS_GEOIP_MMDB</span> or
                    set it to <span className="mono">none</span> to disable. CrowdSec
                    community lists cover most of the same job.
                  </>
                }
              >
                <div className="flex flex-wrap items-center gap-3">
                  {geoip === null ? (
                    <StatusPill tone="neutral">Checking</StatusPill>
                  ) : geoip.configured ? (
                    <StatusPill tone="ok">MMDB ready</StatusPill>
                  ) : (
                    <StatusPill tone="danger">MMDB missing</StatusPill>
                  )}
                </div>
                <p className="mt-3 text-sm text-dim">
                  {geoip === null
                    ? ""
                    : geoip.configured
                      ? <span className="mono text-xs">{geoip.path}</span>
                      : geoip.path
                        ? `MMDB missing at ${geoip.path}. GeoIP is not active; country allow/deny fails closed.`
                        : "No MMDB. Images normally bake DB-IP Country Lite; set AEGIS_GEOIP_MMDB or rebuild api/proxy."}
                </p>
              </Section>
            </div>
          </div>
        </TabPanel>
      </div>

      {userOpen && (
        <UserDialog
          user={editing}
          onClose={() => setUserOpen(false)}
          onSaved={async () => { setUserOpen(false); await load(); }}
        />
      )}
      {openAudit && <AuditDetail e={openAudit} onClose={() => setOpenAudit(null)} />}
    </AppShell>
  );
}

// Every field the audit event recorded. Secrets are never in the summary.
function AuditDetail({ e, onClose }: { e: AuditEvent; onClose: () => void }) {
  const entries = Object.entries(e.summary ?? {});
  return (
    <Dialog
      title={
        <span className="inline-flex items-center gap-2.5">
          <StatusPill tone={actionTone(e.action)}>{e.action}</StatusPill> {e.resource_type}
        </span>
      }
      description={fmtDateTime(e.at)}
      onClose={onClose}
      footer={
        <button type="button" className="btn btn-primary" onClick={onClose}>
          Close
        </button>
      }
    >
      <dl className="space-y-2.5 text-sm">
        <AuditRow label="Who">{e.actor_email || "—"}</AuditRow>
        <AuditRow label="Action">{e.action}</AuditRow>
        <AuditRow label="Resource">
          {e.resource_type} <AuditResource e={e} />
        </AuditRow>
        <AuditRow label="Resource ID">
          <span className="mono break-all text-xs">{e.resource_id || "—"}</span>
        </AuditRow>
        <AuditRow label="Event ID">
          <span className="mono break-all text-xs">{e.id}</span>
        </AuditRow>
      </dl>
      <h3 className="mt-5 text-xs font-semibold uppercase tracking-wide text-faint">Recorded details</h3>
      {entries.length === 0 ? (
        <p className="mt-2 text-sm text-dim">Nothing else was recorded for this change.</p>
      ) : (
        <dl className="mt-2.5 space-y-2 text-sm">
          {entries.map(([k, v]) => (
            <AuditRow key={k} label={k.replace(/_/g, " ")}>
              <span className="mono break-all text-xs">{typeof v === "string" ? v : JSON.stringify(v)}</span>
            </AuditRow>
          ))}
        </dl>
      )}
    </Dialog>
  );
}

function AuditRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[8rem_minmax(0,1fr)] gap-3">
      <dt className="capitalize text-dim">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}




function actionTone(action: string): Tone {
  if (action === "delete") return "danger";
  if (action === "create") return "ok";
  if (action === "update") return "accent";
  return "neutral";
}

function initials(s: string) {
  return (
    s
      .split(/[\s@.]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase())
      .join("") || "?"
  );
}

function PasswordChangeForm({ email }: { email?: string }) {
  const [current, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    setOk(null);
    if (password !== confirm) {
      setErr("New passwords do not match.");
      return;
    }
    if (password.length < 10) {
      setErr("Password must be at least 10 characters.");
      return;
    }
    setBusy(true);
    try {
      await api.changeMyPassword(current, password);
      setCurrent("");
      setPassword("");
      setConfirm("");
      setOk("Password updated. Other sessions are signed out; this one stays signed in.");
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Password change failed");
    } finally {
      setBusy(false);
    }
  }

  const [signingOut, setSigningOut] = useState(false);
  return (
    <Section
      card
      title={<CardTitle icon={KeyRound}>Your password</CardTitle>}
      description={
        <>
          Change the password for {email ? <span className="mono">{email}</span> : "this account"} without another admin.
          Other browsers will need to sign in again.
        </>
      }
    >
      <form onSubmit={onSubmit} className="max-w-md space-y-4">
        {err && <p className="text-sm text-danger">{err}</p>}
        {ok && <p className="text-sm text-ok">{ok}</p>}
        <Field label="Current password">
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
            required
          />
        </Field>
        <Field label="New password">
          <input
            className="input"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={10}
          />
        </Field>
        <Field label="Confirm new password" hint="At least 10 characters.">
          <input
            className="input"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            minLength={10}
          />
        </Field>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? "Saving…" : "Update password"}
        </button>
      </form>
      <div className="mt-6 border-t border-border pt-4">
        <p className="text-sm font-semibold">Sign out everywhere</p>
        <p className="mt-1 text-xs text-faint">
          Ends every session of this account on every device, including this one. Use it if a laptop went missing.
          Sessions also end after 12 hours without use and 7 days at most.
        </p>
        <button
          type="button"
          className="btn btn-secondary mt-3"
          disabled={signingOut}
          onClick={async () => {
            if (!window.confirm("Sign out of Aegis on every device, including this one?")) return;
            setSigningOut(true);
            try {
              await api.revokeAllSessions();
              window.location.href = "/login";
            } catch (e2) {
              setErr(e2 instanceof Error ? e2.message : "Sign-out failed");
              setSigningOut(false);
            }
          }}
        >
          {signingOut ? "Signing out…" : "Sign out everywhere"}
        </button>
      </div>
    </Section>
  );
}

function UserDialog({
  user,
  onClose,
  onSaved,
}: {
  user: User | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = user !== null;
  const [email, setEmail] = useState(user?.email ?? "");
  const [name, setName] = useState(user?.name ?? "");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      if (isEdit) {
        await api.updateUser(user.id, email, name, password || undefined);
      } else {
        await api.createUser(email, name, password);
      }
      onSaved();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={isEdit ? "Edit admin" : "Add admin"}
      size="sm"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form="user-form" className="btn btn-primary" disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <form id="user-form" onSubmit={onSubmit} className="space-y-4">
        {err && <p className="text-sm text-danger">{err}</p>}
        <Field label="Name">
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Email">
          <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </Field>
        <Field
          label={isEdit ? "New password (optional)" : "Password"}
          hint="At least 10 characters. Changing a password signs that user out everywhere."
        >
          <input
            className="input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required={!isEdit}
            minLength={isEdit ? undefined : 10}
          />
        </Field>
      </form>
    </Dialog>
  );
}

// Audit rows name the resource when the summary carries a name; otherwise
// the short id. The API does not join names for deleted resources.
function AuditResource({ e }: { e: AuditEvent }) {
  const sm = e.summary ?? {};
  const pick = (k: string) => {
    const v = sm[k];
    if (typeof v === "string" && v) return v;
    if (Array.isArray(v) && v.length && v.every((x) => typeof x === "string")) return (v as string[]).join(", ");
    return "";
  };
  const name =
    pick("name") || pick("domain_names") || pick("domains") || pick("email") || pick("key") || pick("setting");
  if (name) return <span className="text-fg">{name}</span>;
  // Shorten ids (UUIDs), not names like trusted_proxy.cidrs.
  const id = e.resource_id ?? "";
  return <span className="mono">{/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(id) ? id.slice(0, 8) : id}</span>;
}
