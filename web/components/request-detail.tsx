"use client";

import { ReactNode, useEffect, useState } from "react";
import Link from "next/link";
import { Ban, Check, Copy, ExternalLink, Filter, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { api } from "@/lib/api";
import type { AnalyticsEvent, CrowdSecStatus, Host, Node, WAFMatch } from "@/lib/types";
import { Badge, Dialog, StatusPill } from "@/components/ui";
import { countryName } from "@/lib/countries";
import { fmtMs } from "@/lib/format";
import { stageLabel } from "@/lib/rollups";
import {
  fmtBytes,
  fmtFullTime,
  matchTarget,
  outcomeOf,
  requestsHref,
  severityLabel,
  statusTone,
  type RequestFilters,
} from "@/lib/requests";

// Everything Aegis knows about one request: who sent it, where it went, what
// was asked, and what each security layer decided. Opened from the Overview,
// the live feed and the Requests explorer.
//
// onFilter, when given, applies a filter in place (the Requests explorer);
// otherwise the filter actions are links to it.
export function RequestDetail({
  event: e,
  onClose,
  onFilter,
}: {
  event: AnalyticsEvent;
  onClose: () => void;
  onFilter?: (f: Partial<RequestFilters>) => void;
}) {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [cs, setCs] = useState<CrowdSecStatus | null>(null);

  useEffect(() => {
    // Names for the host and node ids; the dialog works without them.
    api.hosts().then(setHosts).catch(() => undefined);
    api.nodes().then(setNodes).catch(() => undefined);
    api.crowdsecStatus().then(setCs).catch(() => undefined);
  }, []);

  const host = hosts.find((h) => h.id === e.host_id);
  const node = nodes.find((n) => n.id === e.node_id);
  const outcome = outcomeOf(e);
  const via = e.peer_ip && e.peer_ip !== e.client_ip ? e.peer_ip : "";
  // Nodes before 1.7.1 send only the basics.
  const legacy = !e.protocol && !e.id;
  const params = decodedParams(e.query);

  const filterAction = (label: string, f: Partial<RequestFilters>) =>
    onFilter ? (
      <button
        type="button"
        className="btn btn-secondary btn-sm"
        onClick={() => {
          onFilter(f);
          onClose();
        }}
      >
        <Filter size={13} aria-hidden /> {label}
      </button>
    ) : (
      <Link href={requestsHref(f)} className="btn btn-secondary btn-sm">
        <Filter size={13} aria-hidden /> {label}
      </Link>
    );

  return (
    <Dialog
      size="lg"
      onClose={onClose}
      title={
        <span className="flex min-w-0 items-center gap-2.5">
          <StatusPill tone={statusTone(e.status)}>{e.status || "—"}</StatusPill>
          <span className="truncate font-mono text-base">
            <span className="text-faint">{e.method || "—"}</span> {e.path || "/"}
          </span>
        </span>
      }
      description={
        <>
          {e.domain || "—"} · {fmtFullTime(e.timestamp_unix_ms)}
        </>
      }
      footer={
        <>
          <CopyButton text={JSON.stringify(e, null, 2)} label="Copy as JSON" />
          <button type="button" className="btn btn-primary" onClick={onClose}>
            Close
          </button>
        </>
      }
    >
      <OutcomeBanner e={e} />

      {legacy && (
        <p className="mt-3 text-xs text-faint">
          Recorded by a node older than 1.7.1, so the query, upstream, TLS and rule details are missing. Update the proxy to
          record them.
        </p>
      )}

      <div className="mt-5 grid gap-x-8 gap-y-6 md:grid-cols-2">
        <Section title="Source">
          <Item label="Client IP">
            <span className="font-mono">{e.client_ip || "—"}</span>
            {e.client_ip && <CopyButton text={e.client_ip} label="Copy client IP" icon />}
          </Item>
          <Item label="Country">
            {e.country ? (
              <>
                <span className="mr-1.5 rounded-md border border-border-strong bg-panel-2 px-1.5 font-mono text-[11px] text-dim">
                  {e.country}
                </span>
                {countryName(e.country)}
              </>
            ) : (
              <span className="text-faint">Unknown (private or unlisted address)</span>
            )}
          </Item>
          {via && (
            <Item label="Via">
              <span className="font-mono">{via}</span> <span className="text-faint">trusted proxy</span>
            </Item>
          )}
          <Item label="User agent" wrap>
            {e.user_agent ? <span className="font-mono text-xs">{e.user_agent}</span> : <span className="text-faint">None sent</span>}
          </Item>
          {e.referer && (
            <Item label="Referer" wrap>
              <span className="font-mono text-xs">{e.referer}</span>
            </Item>
          )}
        </Section>

        <Section title="Destination">
          <Item label="Host">
            {host ? (
              <Link href="/hosts" className="hover:text-accent">
                {(host.domain_names ?? [])[0] || e.domain}
              </Link>
            ) : (
              e.domain || "—"
            )}
            {e.domain && host && (host.domain_names ?? [])[0] !== e.domain && <span className="text-faint"> as {e.domain}</span>}
          </Item>
          <Item label="Upstream">
            {e.upstream ? (
              <span className="font-mono">{e.upstream}</span>
            ) : (
              <span className="text-faint">{e.block_stage ? "Not reached (blocked)" : legacy ? "—" : "Not reached"}</span>
            )}
          </Item>
          <Item label="Edge node">{node ? node.name : e.node_id ? <span className="font-mono">{e.node_id.slice(0, 8)}</span> : "—"}</Item>
          <Item label="Connection">
            {[e.scheme?.toUpperCase(), e.protocol, e.tls_version].filter(Boolean).join(" · ") || "—"}
          </Item>
        </Section>

        <Section title="Request">
          <Item label="Method">
            <span className="font-mono">{e.method || "—"}</span>
          </Item>
          <Item label="Path" wrap>
            <span className="font-mono text-xs">{e.path || "/"}</span>
          </Item>
          {e.query && (
            <Item label="Query" wrap>
              <span className="font-mono text-xs">{e.query}</span>
            </Item>
          )}
          {params.length > 0 && (
            <Item label="Parameters" wrap>
              <ul className="w-full space-y-1">
                {params.map(([k, v], i) => (
                  <li key={`${k}-${i}`} className="font-mono text-xs">
                    <span className="text-faint">{k} =</span> {v}
                  </li>
                ))}
              </ul>
            </Item>
          )}
          <Item label="Body size">{fmtBytes(e.bytes_received)}</Item>
          {e.id && (
            <Item label="Request ID">
              <span className="font-mono text-xs">{e.id}</span>
              <CopyButton text={e.id} label="Copy request ID" icon />
            </Item>
          )}
        </Section>

        <Section title="Response">
          <Item label="Status">
            <StatusPill tone={statusTone(e.status)}>{e.status || "—"}</StatusPill>
          </Item>
          <Item label="Duration">{fmtMs(e.duration_ms)}</Item>
          <Item label="Sent">{fmtBytes(e.bytes_sent)}</Item>
          <Item label="Outcome">
            <span className={outcome.tone === "danger" ? "text-danger" : outcome.tone === "warn" ? "text-warn" : ""}>{outcome.label}</span>
          </Item>
        </Section>
      </div>

      {(e.waf_action || (e.waf_matches?.length ?? 0) > 0) && (
        <WAFFindings e={e} profileId={host?.waf_profile_id} onFilter={onFilter} onClose={onClose} />
      )}

      <div className="mt-6 flex flex-wrap gap-2 border-t border-border pt-4">
        {e.client_ip && filterAction("Requests from this IP", { ip: e.client_ip })}
        {e.country && filterAction(`Requests from ${countryName(e.country)}`, { country: e.country })}
        {e.host_id && filterAction("Requests to this host", { host_id: e.host_id })}
      </div>

      {cs?.can_ban && e.client_ip && <BanForm ip={e.client_ip} />}
    </Dialog>
  );
}

function OutcomeBanner({ e }: { e: AnalyticsEvent }) {
  const o = outcomeOf(e);
  const Icon = o.tone === "danger" ? ShieldX : o.tone === "warn" ? ShieldAlert : ShieldCheck;
  const tint =
    o.tone === "danger"
      ? "border-danger/40 bg-danger/10"
      : o.tone === "warn"
        ? "border-warn/40 bg-warn/10"
        : "border-ok/30 bg-ok/5";
  const iconTone = o.tone === "danger" ? "text-danger" : o.tone === "warn" ? "text-warn" : "text-ok";
  let detail: ReactNode = null;
  if (e.block_stage) {
    detail = e.block_detail || `The ${stageLabel(e.block_stage)} layer stopped it before it reached the upstream.`;
  } else if (e.waf_action) {
    detail = `The WAF matched ${e.waf_matches?.length || "a"} rule${(e.waf_matches?.length ?? 1) === 1 ? "" : "s"}${
      e.waf_score ? ` (anomaly score ${e.waf_score})` : ""
    } but the profile is in Detect mode, so the request went through.`;
  } else {
    detail = e.upstream ? `Answered by ${e.upstream} in ${fmtMs(e.duration_ms)}.` : `Answered in ${fmtMs(e.duration_ms)}.`;
  }
  return (
    <div className={`flex items-start gap-3 rounded-xl border px-4 py-3 ${tint}`}>
      <Icon size={20} className={`mt-0.5 shrink-0 ${iconTone}`} aria-hidden />
      <div className="min-w-0 text-sm">
        <div className="font-semibold">
          {o.label}
          {e.block_stage === "crowdsec" && e.crowdsec_origin && <span className="font-normal text-dim"> · origin {e.crowdsec_origin}</span>}
        </div>
        <div className="mt-0.5 text-dim">{detail}</div>
      </div>
    </div>
  );
}

function WAFFindings({
  e,
  profileId,
  onFilter,
  onClose,
}: {
  e: AnalyticsEvent;
  profileId?: string;
  onFilter?: (f: Partial<RequestFilters>) => void;
  onClose: () => void;
}) {
  const matches = e.waf_matches ?? [];
  return (
    <section className="mt-6" aria-labelledby="waf-findings-h">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h3 id="waf-findings-h" className="text-sm font-semibold">
          WAF findings
        </h3>
        <Badge tone={e.waf_action === "block" ? "danger" : "warn"}>{e.waf_action === "block" ? "Block" : "Detect"}</Badge>
        {!!e.waf_score && <span className="text-xs text-faint">Anomaly score {e.waf_score}</span>}
      </div>
      {matches.length === 0 ? (
        <p className="mt-2 text-sm text-dim">
          Rule <span className="font-mono">{e.waf_rule_id || "—"}</span>. This node did not report the individual matches.
        </p>
      ) : (
        <ul className="mt-3 space-y-3">
          {matches.map((m, i) => (
            <MatchCard key={`${m.rule_id}-${i}`} m={m} e={e} profileId={profileId} onFilter={onFilter} onClose={onClose} />
          ))}
        </ul>
      )}
    </section>
  );
}

function MatchCard({
  m,
  e,
  profileId,
  onFilter,
  onClose,
}: {
  m: WAFMatch;
  e: AnalyticsEvent;
  profileId?: string;
  onFilter?: (f: Partial<RequestFilters>) => void;
  onClose: () => void;
}) {
  const sev = severityLabel(m.severity);
  const where = matchTarget(m);
  const excludeHref = (scope: "input" | "path" | "all") => {
    if (!profileId) return "";
    const p = new URLSearchParams({ profile: profileId, exclude: m.rule_id });
    if (scope === "input" && where) p.set("target", where);
    if (scope === "path" && e.path) p.set("path", e.path);
    return `/waf?${p.toString()}`;
  };
  const exclude = excludeHref(where ? "input" : "all");
  return (
    <li className="rounded-xl border border-border bg-panel-2/40 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded-md border border-border-strong bg-panel-2 px-1.5 font-mono text-xs">{m.rule_id}</span>
        <Badge tone={sev.tone}>{sev.label}</Badge>
        <span className="min-w-0 text-sm">{m.message}</span>
      </div>
      {where && (
        <div className="mt-2.5 text-xs text-dim">
          Matched in <span className="font-mono text-fg">{where}</span>
        </div>
      )}
      {m.value && (
        <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-bg px-3 py-2 font-mono text-xs text-dim">
          {m.value}
        </pre>
      )}
      <div className="mt-3 flex flex-wrap gap-2">
        {onFilter ? (
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => {
              onFilter({ rule: m.rule_id });
              onClose();
            }}
          >
            <Filter size={13} aria-hidden /> Requests matching {m.rule_id}
          </button>
        ) : (
          <Link href={requestsHref({ rule: m.rule_id })} className="btn btn-ghost btn-sm">
            <Filter size={13} aria-hidden /> Requests matching {m.rule_id}
          </Link>
        )}
        {exclude && (
          <Link href={exclude} className="btn btn-ghost btn-sm" title="Opens this host's WAF profile with the exclusion filled in">
            <ExternalLink size={13} aria-hidden /> {where ? `Exclude ${where} from ${m.rule_id}` : `Exclude rule ${m.rule_id}`}
          </Link>
        )}
        {exclude && where && e.path && (
          <Link href={excludeHref("path")} className="btn btn-ghost btn-sm" title="Turn the rule off under this path only">
            <ExternalLink size={13} aria-hidden /> Off under {e.path}
          </Link>
        )}
        {exclude && where && (
          <Link href={excludeHref("all")} className="btn btn-ghost btn-sm" title="Turn the rule off for every request on this profile">
            <ExternalLink size={13} aria-hidden /> Off everywhere
          </Link>
        )}
      </div>
      {e.waf_action === "block" && m.variable === "REQUEST_COOKIES" && (
        <p className="mt-2 text-xs text-faint">
          A cookie set by another app on the same parent domain (analytics, a CMS) is a common cause; fixing it at the source
          avoids an exclusion.
        </p>
      )}
    </li>
  );
}

function BanForm({ ip }: { ip: string }) {
  const [dur, setDur] = useState("24h");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  async function ban() {
    setBusy(true);
    setMsg(null);
    try {
      const out = await api.crowdsecBan({ ip, duration: dur, reason: "banned from request details" });
      setMsg({ ok: true, text: out.warning || `Banned ${out.value} for ${out.duration}.` });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Ban failed" });
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="mt-4 flex flex-wrap items-center gap-2 rounded-xl border border-border px-4 py-3">
      <Ban size={16} className="text-danger" aria-hidden />
      <span className="text-sm">
        Ban <span className="font-mono">{ip}</span> in CrowdSec for
      </span>
      <select aria-label="Ban duration" className="input h-8 w-28 text-sm" value={dur} onChange={(ev) => setDur(ev.target.value)}>
        <option value="4h">4 hours</option>
        <option value="24h">24 hours</option>
        <option value="7d">7 days</option>
        <option value="30d">30 days</option>
      </select>
      <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={ban}>
        {busy ? "Banning…" : "Ban"}
      </button>
      {msg && (
        <span role="status" className={`w-full text-xs ${msg.ok ? "text-ok" : "text-danger"}`}>
          {msg.text}
        </span>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-faint">{title}</h3>
      <dl className="mt-2.5 space-y-2 text-sm">{children}</dl>
    </section>
  );
}

function Item({ label, wrap, children }: { label: string; wrap?: boolean; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[7rem_minmax(0,1fr)] items-start gap-3">
      <dt className="text-dim">{label}</dt>
      <dd className={`flex min-w-0 items-center gap-1.5 ${wrap ? "break-all" : "truncate"}`}>{children}</dd>
    </div>
  );
}

function CopyButton({ text, label, icon }: { text: string; label: string; icon?: boolean }) {
  const [done, setDone] = useState(false);
  async function copy() {
    if (await copyText(text)) {
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    }
  }
  if (icon) {
    return (
      <button type="button" className="shrink-0 rounded p-1 text-faint hover:text-fg" aria-label={label} title={label} onClick={copy}>
        {done ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />}
      </button>
    );
  }
  return (
    <button type="button" className="btn btn-secondary mr-auto" onClick={copy}>
      {done ? <Check size={15} aria-hidden /> : <Copy size={15} aria-hidden />} {done ? "Copied" : label}
    </button>
  );
}

// The Clipboard API needs HTTPS or localhost; a dashboard opened by LAN IP
// over plain HTTP falls back to a hidden textarea.
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fall through
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  return ok;
}

// Query parameters decoded, shown when decoding changes what the raw query
// says (percent-encoding, +) so an attack payload reads as sent.
function decodedParams(query?: string): [string, string][] {
  if (!query) return [];
  try {
    const out = Array.from(new URLSearchParams(query).entries()).slice(0, 30);
    const raw = query.split("&").map((p) => p.split("="));
    const same = out.length === raw.length && out.every(([k, v], i) => raw[i][0] === k && (raw[i][1] ?? "") === v);
    return same ? [] : out;
  } catch {
    return [];
  }
}
