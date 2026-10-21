"use client";

import { FormEvent, useEffect, useId, useState } from "react";
import { ChevronRight, Gauge, Globe, Plus, Radar, ShieldCheck, Trash2, X } from "lucide-react";
import { api } from "@/lib/api";
import { CountryPicker } from "@/components/country-picker";
import { Dialog, Field, Notice, Switch } from "@/components/ui";
import type { AccessList, Certificate, Host, HostInput, HostKind, HostUpstream, WAFProfile } from "@/lib/types";

export function HostDialog({
  host,
  onClose,
  onSaved,
}: {
  host: Host | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = host !== null;
  const [kind, setKind] = useState<HostKind>(host?.kind ?? "proxy");
  const [domains, setDomains] = useState(host?.domain_names.join(", ") ?? "");
  const [ups, setUps] = useState<UpRow[]>(seedUps(host));
  const [tlsMode, setTlsMode] = useState<Host["tls_mode"]>(host?.tls_mode ?? "auto");
  const [forceHttps, setForceHttps] = useState(host?.force_https ?? true);
  const [hsts, setHsts] = useState(host?.hsts ?? false);
  const [hstsMaxAge, setHstsMaxAge] = useState(String(host?.hsts_max_age || 31536000));
  const [hstsSubdomains, setHstsSubdomains] = useState(host?.hsts_subdomains ?? true);
  const [hstsPreload, setHstsPreload] = useState(host?.hsts_preload ?? false);
  const [websocket, setWebsocket] = useState(host?.websocket_support ?? true);
  const [lbPolicy, setLbPolicy] = useState<"failover" | "round_robin">(host?.lb_policy === "round_robin" ? "round_robin" : "failover");
  const [healthPath, setHealthPath] = useState(host?.health_path ?? "");
  // Host header sent upstream: the client's (default), the upstream's, or custom.
  const initialHostHeader = host?.upstream_host_header ?? "";
  const [hostHeaderMode, setHostHeaderMode] = useState<"client" | "upstream" | "custom">(
    initialHostHeader === "" ? "client" : initialHostHeader === "upstream" ? "upstream" : "custom",
  );
  const [hostHeaderCustom, setHostHeaderCustom] = useState(
    initialHostHeader !== "" && initialHostHeader !== "upstream" ? initialHostHeader : "",
  );
  // Timeouts and limits. Blank = default (shown as placeholder).
  const [idleTimeout, setIdleTimeout] = useState(host?.idle_timeout_seconds ? String(host.idle_timeout_seconds) : "");
  const [upstreamTimeout, setUpstreamTimeout] = useState(
    host?.upstream_response_timeout_seconds ? String(host.upstream_response_timeout_seconds) : "",
  );
  const [maxBodyMB, setMaxBodyMB] = useState(host?.max_body_bytes ? String(Math.round(host.max_body_bytes / 1048576)) : "");
  const [enabled, setEnabled] = useState(host?.enabled ?? true);
  const [certId, setCertId] = useState(host?.cert_id ?? "");
  const [redirectURL, setRedirectURL] = useState(host?.redirect_url ?? "");
  const [redirectCode, setRedirectCode] = useState(String(host?.redirect_code || 301));
  const [listenProto, setListenProto] = useState(host?.listen_protocol || "tcp");
  const [listenPort, setListenPort] = useState(String(host?.listen_port || 19000));
  const [reqHeaders, setReqHeaders] = useState(joinHeaders(host?.request_headers));
  const [respHeaders, setRespHeaders] = useState(joinHeaders(host?.response_headers));
  const [accessListID, setAccessListID] = useState(host?.access_list_id ?? "");
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [lists, setLists] = useState<AccessList[]>([]);
  const [wafProfiles, setWafProfiles] = useState<WAFProfile[]>([]);
  const [geoReady, setGeoReady] = useState(false);
  const [wafProfileID, setWafProfileID] = useState(host?.waf_profile_id ?? "");
  const [rateRps, setRateRps] = useState(String(host?.rate_limit_rps ?? 0));
  const [rateBurst, setRateBurst] = useState(String(host?.rate_limit_burst ?? 0));
  const [geoAllow, setGeoAllow] = useState<string[]>(normalizeCodes(host?.geo_allow));
  const [geoDeny, setGeoDeny] = useState<string[]>(normalizeCodes(host?.geo_deny));
  const [geoOpen, setGeoOpen] = useState<"allow" | "deny" | null>(null);
  const [crowdsec, setCrowdsec] = useState(host?.crowdsec_enabled ?? false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [headersOpen, setHeadersOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [loadErrs, setLoadErrs] = useState<string[]>([]);

  useEffect(() => {
    // Lookups feed the pickers. A failure is shown, not swallowed, so an
    // empty certificate or access-list picker is never mistaken for "none".
    const fail = (what: string) => () => setLoadErrs((cur) => (cur.includes(what) ? cur : [...cur, what]));
    api.certificates().then(setCerts).catch(fail("certificates"));
    api.accessLists().then(setLists).catch(fail("access lists"));
    api.wafProfiles().then(setWafProfiles).catch(fail("WAF profiles"));
    api.geoipStatus().then((g) => setGeoReady(!!(g.ready ?? g.configured))).catch(fail("GeoIP status"));
  }, []);

  const httpKind = kind === "proxy" || kind === "redirect" || kind === "dead";

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    const domainList = domains.split(",").map((d) => d.trim()).filter(Boolean);
    if (domainList.length === 0) return setErr("At least one name is required.");

    const cleaned = ups
      .map((u) => {
        const row: HostUpstream = {
          scheme: kind === "stream" ? "http" : (u.scheme || "http"),
          host: u.host.trim(),
          port: parseInt(u.port, 10) || 0,
        };
        const w = parseInt(u.weight, 10);
        if (lbPolicy === "round_robin" && w > 1) row.weight = w;
        if (row.scheme === "https") {
          if (u.skipVerify) row.tls_skip_verify = true;
          if (u.sni.trim()) row.tls_server_name = u.sni.trim();
          if (u.caPem.trim()) row.tls_ca_pem = u.caPem.trim();
        }
        return row;
      })
      .filter((u) => u.host && u.port > 0);
    const first = cleaned[0];
    // A half-filled row is a mistake, not something to drop silently (that
    // could quietly promote the backup to primary).
    const partial = ups.find((u) => (u.host.trim() !== "") !== (parseInt(u.port, 10) > 0) || (u.port !== "" && !(parseInt(u.port, 10) >= 1 && parseInt(u.port, 10) <= 65535)));
    if (kind !== "redirect" && kind !== "dead" && partial) {
      return setErr(`Upstream "${partial.host || "(no host)"}:${partial.port || "(no port)"}" needs both a host and a port 1–65535, or remove the row.`);
    }

    const payload: HostInput = {
      kind,
      domain_names: domainList,
      upstream_scheme: first?.scheme || "http",
      upstream_host: first?.host || "",
      upstream_port: first?.port || 0,
      upstreams: cleaned,
      lb_policy: kind === "proxy" && lbPolicy === "round_robin" ? "round_robin" : "",
      health_path: kind === "proxy" ? healthPath.trim() : "",
      enabled,
      tls_mode: kind === "stream" ? "none" : tlsMode,
      cert_id: tlsMode === "custom" && kind !== "stream" ? certId : undefined,
      force_https: kind === "stream" ? false : forceHttps,
      hsts: kind === "stream" ? false : hsts,
      hsts_max_age: parseInt(hstsMaxAge, 10) || 31536000,
      hsts_subdomains: hstsSubdomains,
      hsts_preload: hstsPreload,
      websocket_support: kind === "proxy" ? websocket : false,
      upstream_host_header:
        kind !== "proxy" || hostHeaderMode === "client"
          ? ""
          : hostHeaderMode === "upstream"
            ? "upstream"
            : hostHeaderCustom.trim(),
      idle_timeout_seconds: kind === "proxy" ? parseInt(idleTimeout, 10) || 0 : 0,
      upstream_response_timeout_seconds: kind === "proxy" ? parseInt(upstreamTimeout, 10) || 0 : 0,
      max_body_bytes: kind === "proxy" ? (parseInt(maxBodyMB, 10) || 0) * 1048576 : 0,
      redirect_url: redirectURL,
      redirect_code: parseInt(redirectCode, 10) || 301,
      request_headers: parseHeaders(reqHeaders),
      response_headers: parseHeaders(respHeaders),
      access_list_id: accessListID || undefined,
      listen_protocol: listenProto,
      listen_port: parseInt(listenPort, 10) || 0,
      waf_profile_id: wafProfileID || undefined,
      rate_limit_rps: parseInt(rateRps, 10) || 0,
      rate_limit_burst: parseInt(rateBurst, 10) || 0,
      geo_allow: geoAllow,
      geo_deny: geoDeny,
      crowdsec_enabled: crowdsec,
      oidc: { enabled: false, issuer: "", client_id: "", client_secret: "", paths: [], cookie_name: "" },
    };

    if (kind === "proxy") {
      if (cleaned.length === 0) return setErr("At least one upstream host and port is required.");
      for (const [label, v] of [["Idle timeout", idleTimeout], ["Upstream response timeout", upstreamTimeout]] as const) {
        if (v !== "" && (!/^\d+$/.test(v) || parseInt(v, 10) > 3600)) return setErr(`${label} must be 1–3600 seconds, or blank for the default.`);
      }
      if (maxBodyMB !== "" && (!/^\d+$/.test(maxBodyMB) || parseInt(maxBodyMB, 10) > 65536)) return setErr("Max request body must be a whole number of MB, or blank for no limit.");
      if (hostHeaderMode === "custom" && !hostHeaderCustom.trim()) return setErr("Enter the Host header to send upstream, or choose the client's Host.");
      if (healthPath.trim() && !healthPath.trim().startsWith("/")) return setErr("The health check path must start with /.");
      const badWeight = ups.find((u) => u.weight !== "" && !(parseInt(u.weight, 10) >= 1 && parseInt(u.weight, 10) <= 100));
      if (lbPolicy === "round_robin" && badWeight) return setErr("Upstream weights must be 1–100.");
    }
    if (kind === "redirect" && !redirectURL) return setErr("Redirect URL is required.");
    if (kind === "stream") {
      if (cleaned.length === 0) return setErr("At least one upstream host and port is required.");
      if (!payload.listen_port) return setErr("Listen and upstream ports are required.");
    }

    setBusy(true);
    try {
      if (isEdit) await api.updateHost(host.id, payload);
      else await api.createHost(payload);
      onSaved();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Save failed.");
    } finally {
      setBusy(false);
    }
  }

  async function onDelete() {
    if (!host) return;
    setErr(null);
    setBusy(true);
    try {
      await api.deleteHost(host.id);
      onSaved();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Delete failed.");
      setConfirmDelete(false);
    } finally {
      setBusy(false);
    }
  }

  const footer =
    confirmDelete && host ? (
      <>
        <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => setConfirmDelete(false)}>
          Keep host
        </button>
        <button type="button" className="btn btn-danger" disabled={busy} onClick={onDelete}>
          <Trash2 size={15} aria-hidden /> {busy ? "Deleting…" : "Delete host"}
        </button>
      </>
    ) : (
      <>
        {isEdit && (
          <button type="button" className="btn btn-danger mr-auto" disabled={busy} onClick={() => setConfirmDelete(true)}>
            <Trash2 size={15} aria-hidden /> Delete
          </button>
        )}
        <button type="button" className="btn btn-secondary" onClick={onClose}>
          Cancel
        </button>
        <button type="submit" form="host-form" className="btn btn-primary" disabled={busy}>
          {busy ? "Saving…" : isEdit ? "Save changes" : "Create host"}
        </button>
      </>
    );

  const layersOn = [
    !!wafProfileID,
    crowdsec,
    geoAllow.length + geoDeny.length > 0,
    (parseInt(rateRps, 10) || 0) > 0,
  ].filter(Boolean).length;

  return (
    <>
    <Dialog
      busy={busy}
      confirmClose={dirty ? "Discard the changes to this host?" : undefined}
      title={isEdit ? "Edit host" : "Add host"}
      description="Routing, TLS, and the security layers in front of this host."
      onClose={onClose}
      footer={footer}
      size="lg"
    >
        <form id="host-form" onSubmit={onSubmit} onChange={() => setDirty(true)} className="space-y-5">
          {err && <Notice tone="danger" title={err} />}
          {loadErrs.length > 0 && (
            <Notice tone="warn" title="Some pickers may be incomplete">
              Could not load {loadErrs.join(", ")}.
            </Notice>
          )}

          <Segmented
            label="Kind"
            value={kind}
            onChange={(v) => setKind(v as HostKind)}
            options={[
              { value: "proxy", label: "Proxy" },
              { value: "redirect", label: "Redirect" },
              { value: "dead", label: "404" },
              { value: "stream", label: "TCP/UDP stream" },
            ]}
          />

          <Field label={kind === "stream" ? "Name" : "Domain names"} hint={kind === "stream" ? "Label only — not used for SNI. Must be unique." : "Comma-separated. Unique across hosts. Wildcards like *.example.com use DNS-01."}>
            <input
              className="input mono"
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              placeholder={kind === "stream" ? "minecraft" : "app.example.com"}
              autoFocus
            />
          </Field>

          {kind === "redirect" && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
              <div className="sm:col-span-3">
                <Field label="Redirect URL">
                  <input className="input mono" value={redirectURL} onChange={(e) => setRedirectURL(e.target.value)} placeholder="https://example.com" />
                </Field>
              </div>
              <Field label="Code">
                <select className="input" value={redirectCode} onChange={(e) => setRedirectCode(e.target.value)}>
                  <option value="301">301</option>
                  <option value="302">302</option>
                </select>
              </Field>
            </div>
          )}

          {(kind === "proxy" || kind === "stream") && (
            <section aria-labelledby="ups-h" className="space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h3 id="ups-h" className="text-sm font-semibold">Upstreams</h3>
                  <p className="text-xs text-faint">
                    {kind !== "proxy" || lbPolicy === "failover"
                      ? "First healthy origin is used. Order is failover priority."
                      : "Requests rotate over healthy origins in proportion to their weights."}
                  </p>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm shrink-0"
                  onClick={() => setUps((cur) => [...cur, emptyUp(cur[0]?.scheme || "http", kind === "stream" ? "" : "80")])}
                >
                  <Plus size={14} strokeWidth={2.4} aria-hidden /> {kind === "proxy" && lbPolicy === "round_robin" ? "Add upstream" : "Add backup"}
                </button>
              </div>
              {ups.map((u, i) => (
                <div key={i} className="space-y-3 rounded-xl border border-border-strong bg-bg/40 p-3.5">
                  <div className="flex items-center justify-between">
                    <span className={`text-xs font-bold ${i === 0 || (kind === "proxy" && lbPolicy === "round_robin") ? "text-accent" : "text-dim"}`}>
                      {kind === "proxy" && lbPolicy === "round_robin" ? `Upstream ${i + 1}` : i === 0 ? "Primary" : `Backup ${i}`}
                    </span>
                    {ups.length > 1 && (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        aria-label={`Remove ${i === 0 ? "primary" : `backup ${i}`} upstream`}
                        onClick={() => setUps((cur) => cur.filter((_, j) => j !== i))}
                      >
                        <X size={14} aria-hidden /> Remove
                      </button>
                    )}
                  </div>
                  <div className={`grid items-end gap-3 ${kind === "proxy" ? (lbPolicy === "round_robin" ? "grid-cols-[5.5rem_minmax(0,1fr)_5rem_4.5rem] sm:grid-cols-[7rem_minmax(0,1fr)_6rem_5rem]" : "grid-cols-[5.5rem_minmax(0,1fr)_5rem] sm:grid-cols-[7rem_minmax(0,1fr)_6rem]") : "grid-cols-[minmax(0,1fr)_5rem] sm:grid-cols-[minmax(0,1fr)_6rem]"}`}>
                    {kind === "proxy" && (
                      <Field label="Scheme">
                        <select
                          className="input"
                          value={u.scheme}
                          onChange={(e) => {
                            const v = e.target.value;
                            setUps((cur) => cur.map((x, j) => (j === i ? { ...x, scheme: v } : x)));
                          }}
                        >
                          <option value="http">http</option>
                          <option value="https">https</option>
                        </select>
                      </Field>
                    )}
                    <Field label="Host">
                      <input
                        className="input mono"
                        value={u.host}
                        placeholder="10.0.0.5"
                        onChange={(e) => {
                          const v = e.target.value;
                          setUps((cur) => cur.map((x, j) => (j === i ? { ...x, host: v } : x)));
                        }}
                      />
                    </Field>
                    <Field label="Port">
                      <input
                        className="input mono"
                        type="number"
                        value={u.port}
                        onChange={(e) => {
                          const v = e.target.value;
                          setUps((cur) => cur.map((x, j) => (j === i ? { ...x, port: v } : x)));
                        }}
                      />
                    </Field>
                    {kind === "proxy" && lbPolicy === "round_robin" && (
                      <Field label="Weight">
                        <input
                          className="input mono"
                          type="number"
                          min={1}
                          max={100}
                          placeholder="1"
                          value={u.weight}
                          onChange={(e) => {
                            const v = e.target.value;
                            setUps((cur) => cur.map((x, j) => (j === i ? { ...x, weight: v } : x)));
                          }}
                        />
                      </Field>
                    )}
                  </div>
                  {kind === "proxy" && u.scheme === "https" && (
                    <div className="space-y-3 border-t border-border pt-3">
                      <Switch
                        label="Skip TLS verify"
                        description="Self-signed origin. Prefer a custom CA PEM when you have one."
                        checked={u.skipVerify}
                        onChange={(v) => setUps((cur) => cur.map((x, j) => (j === i ? { ...x, skipVerify: v } : x)))}
                      />
                      <Field label="SNI override" hint="Required when the origin is an IP. Leave empty to use the host.">
                        <input
                          className="input mono"
                          value={u.sni}
                          placeholder="app.internal"
                          onChange={(e) => {
                            const v = e.target.value;
                            setUps((cur) => cur.map((x, j) => (j === i ? { ...x, sni: v } : x)));
                          }}
                        />
                      </Field>
                      <Field label="Custom CA PEM" hint="Added to the system trust store for this origin. Ignored when skip-verify is on.">
                        <textarea
                          className="input mono min-h-20"
                          value={u.caPem}
                          disabled={u.skipVerify}
                          placeholder="-----BEGIN CERTIFICATE-----"
                          onChange={(e) => {
                            const v = e.target.value;
                            setUps((cur) => cur.map((x, j) => (j === i ? { ...x, caPem: v } : x)));
                          }}
                        />
                      </Field>
                    </div>
                  )}
                </div>
              ))}
              {kind === "proxy" && (
                <div className="grid gap-3 border-t border-border pt-3 sm:grid-cols-2">
                  <Field label="Selection" hint={lbPolicy === "failover" ? "Backups take over only when the primary fails." : "Weights set each origin's share; a down origin is skipped."}>
                    <select className="input" value={lbPolicy} onChange={(e) => setLbPolicy(e.target.value as "failover" | "round_robin")}>
                      <option value="failover">Failover (first healthy wins)</option>
                      <option value="round_robin">Round robin (weighted)</option>
                    </select>
                  </Field>
                  <Field label="Health check path" hint="GET every 5 s on each origin; any answer below 500 is healthy. Blank = TCP connect check.">
                    <input className="input mono" value={healthPath} placeholder="/healthz" onChange={(e) => setHealthPath(e.target.value)} />
                  </Field>
                </div>
              )}
            </section>
          )}

          {kind === "proxy" && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <Field
                label="Host header sent upstream"
                hint={
                  hostHeaderMode === "client"
                    ? "The name the visitor used. Keeps vhost routing, absolute URLs and WebSocket origin checks working."
                    : hostHeaderMode === "upstream"
                      ? "The upstream's own host:port. Use for origins that only answer to their own name."
                      : "Sent exactly as entered."
                }
              >
                <select
                  className="input"
                  value={hostHeaderMode}
                  onChange={(e) => setHostHeaderMode(e.target.value as "client" | "upstream" | "custom")}
                >
                  <option value="client">Client&apos;s Host (recommended)</option>
                  <option value="upstream">Upstream address</option>
                  <option value="custom">Custom</option>
                </select>
              </Field>
              {hostHeaderMode === "custom" && (
                <Field label="Custom Host">
                  <input
                    className="input font-mono"
                    value={hostHeaderCustom}
                    onChange={(e) => setHostHeaderCustom(e.target.value)}
                    placeholder="app.internal"
                    spellCheck={false}
                  />
                </Field>
              )}
            </div>
          )}

          {kind === "proxy" && (
            <fieldset className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <legend className="mb-2 text-sm text-dim">Timeouts and limits</legend>
              <Field label="Idle timeout (s)" hint="Cut a request when no data moves either way for this long. Slow but live transfers are fine. Blank = 60.">
                <input className="input mono" inputMode="numeric" placeholder="60" value={idleTimeout} onChange={(e) => setIdleTimeout(e.target.value)} />
              </Field>
              <Field label="Upstream response timeout (s)" hint="How long to wait for the app's first byte before 504. Raise for slow reports. Blank = 60.">
                <input className="input mono" inputMode="numeric" placeholder="60" value={upstreamTimeout} onChange={(e) => setUpstreamTimeout(e.target.value)} />
              </Field>
              <Field label="Max request body (MB)" hint="Larger requests get 413 at the edge. Blank = no limit (the app decides).">
                <input className="input mono" inputMode="numeric" placeholder="no limit" value={maxBodyMB} onChange={(e) => setMaxBodyMB(e.target.value)} />
              </Field>
            </fieldset>
          )}

          {kind === "stream" && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Listen protocol">
                <select className="input" value={listenProto} onChange={(e) => setListenProto(e.target.value)}>
                  <option value="tcp">tcp</option>
                  <option value="udp">udp</option>
                </select>
              </Field>
              <Field label="Listen port" hint="Must be published on the proxy container (compose e2e range 19000–19002).">
                <input className="input mono" type="number" value={listenPort} onChange={(e) => setListenPort(e.target.value)} />
              </Field>
            </div>
          )}

          {httpKind && (
            <Segmented
              label="TLS"
              value={tlsMode}
              onChange={(v) => setTlsMode(v as Host["tls_mode"])}
              hint={tlsMode === "auto" ? "Issues Let's Encrypt on save, or reuses a covering cert requested on Certificates first." : tlsMode === "none" ? "Traffic to this host is not encrypted." : undefined}
              options={[
                { value: "auto", label: "Auto (ACME)" },
                { value: "custom", label: "Existing cert" },
                { value: "none", label: "HTTP only" },
              ]}
            />
          )}

          {httpKind && tlsMode === "custom" && (
            <Field label="Certificate" hint="Request Let's Encrypt or upload a PEM on Certificates first.">
              <select className="input" value={certId} onChange={(e) => setCertId(e.target.value)} required>
                <option value="">Select a certificate…</option>
                {certs.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.domains.join(", ")} ({c.issuer})
                  </option>
                ))}
              </select>
            </Field>
          )}

          <Field label="Access list" hint="Basic auth and IP allow/deny, checked before the security layers.">
            <select className="input" value={accessListID} onChange={(e) => setAccessListID(e.target.value)}>
              <option value="">None</option>
              {lists.map((a) => (
                <option key={a.id} value={a.id}>{a.name}</option>
              ))}
            </select>
          </Field>

          {kind === "proxy" && (
            <section aria-labelledby="sec-h" className="space-y-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <div>
                  <h3 id="sec-h" className="text-sm font-semibold">Security layers</h3>
                  <p className="text-xs text-faint">
                    Run in order: CrowdSec → GeoIP → rate limit → WAF. WebSocket handshakes pass through them; frames after upgrade do not.
                  </p>
                </div>
                <span className={`shrink-0 rounded-full px-2.5 py-1 text-xs font-bold ${layersOn > 0 ? "bg-ok/10 text-ok" : "bg-warn/10 text-warn"}`}>
                  {layersOn} of 4 layers on
                </span>
              </div>
              <LayerRow
                icon={<ShieldCheck size={18} aria-hidden />}
                title="WAF"
                on={!!wafProfileID}
                description="OWASP Core Rule Set via a profile from WAF policies."
              >
                <select
                  className="input"
                  aria-label="WAF profile"
                  value={wafProfileID}
                  onChange={(e) => setWafProfileID(e.target.value)}
                >
                  <option value="">Off</option>
                  {wafProfiles.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.mode === "detect" ? "detect" : "block"} · PL{p.paranoia || 1})
                    </option>
                  ))}
                </select>
              </LayerRow>

              <LayerRow
                icon={<Radar size={18} aria-hidden />}
                title="CrowdSec"
                on={crowdsec}
                description="L7 bans from this host's own log scenarios. Community lists and manual bans run on the host firewall."
                control={
                  <Switch
                    label={<span className="sr-only">CrowdSec</span>}
                    checked={crowdsec}
                    onChange={setCrowdsec}
                  />
                }
              />

              <LayerRow
                icon={<Globe size={18} aria-hidden />}
                title="GeoIP"
                on={geoAllow.length + geoDeny.length > 0}
                description={geoReady ? "Allow or deny by country. A country cannot be on both lists." : "Country database missing: lists fail closed (403) until it loads."}
              >
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <CountryPicker
                    label="Allow only"
                    hint="Empty allows every country."
                    selected={geoAllow}
                    onChange={(next) => {
                      setGeoAllow(next);
                      setGeoDeny((cur) => cur.filter((c) => !next.includes(c)));
                    }}
                    open={geoOpen === "allow"}
                    onToggle={() => setGeoOpen(geoOpen === "allow" ? null : "allow")}
                  />
                  <CountryPicker
                    label="Deny"
                    selected={geoDeny}
                    onChange={(next) => {
                      setGeoDeny(next);
                      setGeoAllow((cur) => cur.filter((c) => !next.includes(c)));
                    }}
                    open={geoOpen === "deny"}
                    onToggle={() => setGeoOpen(geoOpen === "deny" ? null : "deny")}
                  />
                </div>
              </LayerRow>

              <LayerRow
                icon={<Gauge size={18} aria-hidden />}
                title="Rate limit"
                on={(parseInt(rateRps, 10) || 0) > 0}
                description="Requests per second per client IP. 0 turns the layer off."
              >
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Requests / second">
                    <input className="input mono" type="number" min={0} value={rateRps} onChange={(e) => setRateRps(e.target.value)} />
                  </Field>
                  <Field label="Burst">
                    <input className="input mono" type="number" min={0} value={rateBurst} onChange={(e) => setRateBurst(e.target.value)} />
                  </Field>
                </div>
              </LayerRow>
            </section>
          )}

          <section aria-label="Options" className="grid grid-cols-1 gap-x-6 rounded-xl border border-border px-4 py-1 sm:grid-cols-2">
            {httpKind && tlsMode !== "none" && (
              <>
                <Switch label="Force HTTPS" checked={forceHttps} onChange={setForceHttps} />
                <Switch label="HSTS" checked={hsts} onChange={setHsts} />
              </>
            )}
            {httpKind && tlsMode !== "none" && hsts && (
              <div className="col-span-full grid grid-cols-1 gap-3 border-t border-border py-3 sm:grid-cols-3">
                <Field label="HSTS max-age" hint="How long browsers insist on HTTPS for this name.">
                  <select className="input" value={hstsMaxAge} onChange={(e) => setHstsMaxAge(e.target.value)}>
                    <option value="15768000">6 months</option>
                    <option value="31536000">1 year</option>
                    <option value="63072000">2 years</option>
                  </select>
                </Field>
                <div className="sm:col-span-2">
                  <Switch label="Include subdomains" checked={hstsSubdomains} onChange={(v) => { setHstsSubdomains(v); if (!v) setHstsPreload(false); }} />
                  <Switch
                    label="Preload (submit to hstspreload.org yourself)"
                    checked={hstsPreload}
                    onChange={(v) => { setHstsPreload(v); if (v) { setHstsSubdomains(true); if (parseInt(hstsMaxAge, 10) < 31536000) setHstsMaxAge("31536000"); } }}
                  />
                  {hstsSubdomains && (
                    <p className="mt-1 text-xs text-warn">
                      Every subdomain of this name must serve HTTPS for the whole max-age, including internal ones browsers on this network visit.
                    </p>
                  )}
                </div>
              </div>
            )}
            {kind === "proxy" && <Switch label="WebSockets" checked={websocket} onChange={setWebsocket} />}
            {kind === "proxy" && (
              <div className="py-2">
                <button
                  type="button"
                  onClick={() => setHeadersOpen(true)}
                  className="group flex w-full items-center justify-between gap-4 text-left text-sm"
                >
                  <span className="text-dim group-hover:text-fg">Custom headers</span>
                  <span className="inline-flex items-center gap-1 text-xs text-faint group-hover:text-fg">
                    {headerSummary(reqHeaders, respHeaders)} <ChevronRight size={14} aria-hidden />
                  </span>
                </button>
              </div>
            )}
            <Switch label="Enabled" checked={enabled} onChange={setEnabled} />
          </section>

          {confirmDelete && host && (
            <Notice tone="danger" title={`Delete ${host.domain_names.join(", ")}?`}>
              Traffic to these domains stops as soon as the config reaches the edge.
            </Notice>
          )}
        </form>
    </Dialog>

      {headersOpen && (
        <SecondaryPanel
          title="Headers"
          hint="One header per line: Name: value"
          onDone={() => setHeadersOpen(false)}
        >
          <Field label="Request headers">
            <textarea className="input mono min-h-28" value={reqHeaders} onChange={(e) => setReqHeaders(e.target.value)} />
          </Field>
          <Field label="Response headers">
            <textarea className="input mono min-h-28" value={respHeaders} onChange={(e) => setRespHeaders(e.target.value)} />
          </Field>
        </SecondaryPanel>
      )}
    </>
  );
}

// One-of-N choice as a row of pills (radio group semantics, arrow keys).
function Segmented({
  label,
  value,
  options,
  onChange,
  hint,
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
  hint?: string;
}) {
  const id = useId();
  function onKey(e: React.KeyboardEvent, i: number) {
    let n = -1;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") n = (i + 1) % options.length;
    if (e.key === "ArrowLeft" || e.key === "ArrowUp") n = (i - 1 + options.length) % options.length;
    if (n < 0) return;
    e.preventDefault();
    onChange(options[n].value);
    const el = (e.currentTarget.parentElement?.children[n] as HTMLElement | undefined);
    el?.focus();
  }
  return (
    <div className="space-y-1.5">
      <div id={`${id}-l`} className="text-sm text-dim">{label}</div>
      <div role="radiogroup" aria-labelledby={`${id}-l`} aria-describedby={hint ? `${id}-h` : undefined} className="flex flex-wrap gap-2">
        {options.map((o, i) => {
          const on = o.value === value;
          return (
            <button
              key={o.value}
              type="button"
              role="radio"
              aria-checked={on}
              tabIndex={on ? 0 : -1}
              onClick={() => onChange(o.value)}
              onKeyDown={(e) => onKey(e, i)}
              className={`h-9 rounded-full px-4 text-[13px] font-bold transition-colors ${
                on ? "bg-accent text-ink" : "border border-border-strong text-dim hover:border-border-hover hover:text-fg"
              }`}
            >
              {o.label}
            </button>
          );
        })}
      </div>
      {hint && <p id={`${id}-h`} className="text-xs text-faint">{hint}</p>}
    </div>
  );
}

// One security layer: icon, name, on/off state, explanation, and its controls.
function LayerRow({
  icon,
  title,
  description,
  on,
  control,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  on: boolean;
  control?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div className={`rounded-xl border p-3.5 transition-colors ${on ? "border-accent/30 bg-accent/[0.04]" : "border-border-strong bg-bg/40"}`}>
      <div className="flex items-start gap-3">
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-[10px] border ${on ? "border-accent/30 bg-accent/10 text-accent" : "border-border-strong bg-panel-2 text-faint"}`}>
          {icon}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-semibold">{title}</span>
            <span className={`text-xs font-bold ${on ? "text-accent" : "text-faint"}`}>{on ? "On" : "Off"}</span>
          </div>
          <p className="mt-0.5 text-xs text-faint">{description}</p>
        </div>
        {control && <div className="w-12 shrink-0">{control}</div>}
      </div>
      {children && <div className="mt-3 sm:pl-12">{children}</div>}
    </div>
  );
}

function headerSummary(reqRaw: string, respRaw: string) {
  const req = Object.keys(parseHeaders(reqRaw)).length;
  const resp = Object.keys(parseHeaders(respRaw)).length;
  if (!req && !resp) return "None";
  const parts: string[] = [];
  if (req) parts.push(`${req} request`);
  if (resp) parts.push(`${resp} response`);
  return parts.join(", ");
}

function normalizeCodes(raw?: string[]) {
  return (raw ?? []).map((s) => s.trim().toUpperCase()).filter(Boolean);
}

function SecondaryPanel({
  title,
  hint,
  onDone,
  children,
}: {
  title: string;
  hint?: string;
  onDone: () => void;
  children: React.ReactNode;
}) {
  return (
    <Dialog
      title={title}
      description={hint}
      onClose={onDone}
      layer={1}
      footer={
        <button type="button" className="btn btn-primary" onClick={onDone}>
          Done
        </button>
      }
    >
      <div className="space-y-4">{children}</div>
    </Dialog>
  );
}

function joinHeaders(m?: Record<string, string>) {
  if (!m) return "";
  return Object.entries(m).map(([k, v]) => `${k}: ${v}`).join("\n");
}

type UpRow = { scheme: string; host: string; port: string; weight: string; skipVerify: boolean; sni: string; caPem: string };

function emptyUp(scheme: string, port: string): UpRow {
  return { scheme, host: "", port, weight: "", skipVerify: false, sni: "", caPem: "" };
}

function seedUps(host: Host | null): UpRow[] {
  const fromList = (host?.upstreams ?? []).filter((u) => u.host);
  if (fromList.length) {
    return fromList.map((u) => ({
      scheme: u.scheme || "http",
      host: u.host,
      port: String(u.port || 80),
      weight: u.weight && u.weight > 1 ? String(u.weight) : "",
      skipVerify: !!u.tls_skip_verify,
      sni: u.tls_server_name || "",
      caPem: u.tls_ca_pem || "",
    }));
  }
  if (host?.upstream_host) {
    return [{
      scheme: host.upstream_scheme || "http",
      host: host.upstream_host,
      port: String(host.upstream_port || 80),
      weight: "",
      skipVerify: false,
      sni: "",
      caPem: "",
    }];
  }
  return [emptyUp("http", "80")];
}

function parseHeaders(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of raw.split("\n")) {
    const i = line.indexOf(":");
    if (i < 1) continue;
    const k = line.slice(0, i).trim();
    const v = line.slice(i + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}
