// Security posture: a small set of checks computed from data the dashboard
// already loads, and a 0–100 score that is their weighted sum. The checks are
// always shown next to the score, so the number is never a black box.

import type { Certificate, CrowdSecStatus, Host, Node } from "@/lib/types";
import { daysUntil } from "@/lib/format";

export type CheckState = "pass" | "warn" | "fail";

export type PostureCheck = {
  id: string;
  title: string;
  detail: string;
  state: CheckState;
  href: string;
  // Link text for href; says where it goes.
  action: string;
  // What the check is about when it does not pass (host or node names).
  names: string[];
  weight: number;
  // Share of the weight earned, 0–1.
  earned: number;
};

export type Posture = { score: number; checks: PostureCheck[]; issues: number };

export function computePosture(input: {
  nodes: Node[];
  hosts: Host[];
  certs: Certificate[];
  crowdsec: CrowdSecStatus | null;
}): Posture {
  const { nodes, hosts, certs, crowdsec } = input;
  const checks: PostureCheck[] = [];

  // Edge nodes online.
  const active = nodes.filter((n) => !n.revoked);
  const online = active.filter((n) => n.online).length;
  checks.push({
    id: "nodes",
    title: active.length === 0 ? "No edge nodes enrolled" : `${online} of ${active.length} edge node${active.length === 1 ? "" : "s"} online`,
    detail: active.length === 0 ? "Enrol a proxy to serve traffic" : online === active.length ? "Every node is taking config" : "Offline nodes serve their last config",
    state: active.length === 0 || online === 0 ? "fail" : online < active.length ? "warn" : "pass",
    href: "/nodes",
    action: "Open nodes",
    names: active.filter((n) => !n.online).map((n) => n.name),
    weight: 25,
    earned: active.length === 0 ? 0 : online / active.length,
  });

  // WAF coverage on enabled proxy hosts.
  const proxies = hosts.filter((h) => h.enabled && h.kind === "proxy");
  const waf = proxies.filter((h) => h.waf_profile_id).length;
  const wafShare = proxies.length === 0 ? 1 : waf / proxies.length;
  checks.push({
    id: "waf",
    title: proxies.length === 0 ? "No proxy hosts yet" : `WAF on ${waf} of ${proxies.length} proxy host${proxies.length === 1 ? "" : "s"}`,
    detail:
      waf === proxies.length
        ? "OWASP CRS inspects every proxied request"
        : `${proxies.length - waf} host${proxies.length - waf === 1 ? "" : "s"} unprotected`,
    state: wafShare >= 1 ? "pass" : wafShare >= 0.5 ? "warn" : "fail",
    href: "/hosts",
    action: "Open hosts",
    names: proxies.filter((h) => !h.waf_profile_id).map((h) => h.domain_names[0] ?? "(unnamed)"),
    weight: 25,
    earned: wafShare,
  });

  // CrowdSec reachable.
  const csOk = !!crowdsec?.configured && !!crowdsec.lapi_ok;
  checks.push({
    id: "crowdsec",
    title: csOk ? "CrowdSec community blocklists active" : "CrowdSec not connected",
    detail: csOk
      ? `Firewall ${crowdsec?.firewall_enabled ? "on" : "off"}`
      : crowdsec?.configured
        ? "LAPI is not reachable"
        : "Bouncer key not set",
    state: csOk ? "pass" : "fail",
    href: "/settings#crowdsec",
    action: "Open settings",
    names: [],
    weight: 15,
    earned: csOk ? 1 : 0,
  });

  // Certificates: none expired, none expiring within 14 days.
  const expired = certs.filter((c) => (daysUntil(c.expires_at) ?? 1) < 0).length;
  const soon = certs.filter((c) => {
    const d = daysUntil(c.expires_at);
    return d !== null && d >= 0 && d <= 14;
  }).length;
  checks.push({
    id: "certs",
    title:
      expired > 0
        ? `${expired} certificate${expired === 1 ? "" : "s"} expired`
        : soon > 0
          ? `${soon} certificate${soon === 1 ? " expires" : "s expire"} within 14 days`
          : "All certificates valid",
    detail: expired > 0 ? "Delete or replace expired certificates" : soon > 0 ? "Renew before they lapse" : "Nothing expires in the next 14 days",
    state: expired > 0 ? "fail" : soon > 0 ? "warn" : "pass",
    href: "/certificates",
    action: "Open certificates",
    // The certificates the title counts: the expired ones when any are,
    // otherwise the ones about to expire.
    // Deduplicated: a replaced certificate can leave two for one name.
    names: Array.from(
      new Set(
        certs
          .filter((c) => {
            const d = daysUntil(c.expires_at);
            return d !== null && (expired > 0 ? d < 0 : d >= 0 && d <= 14);
          })
          .map((c) => c.domains?.[0] ?? "")
          .filter(Boolean),
      ),
    ),
    weight: 20,
    earned: expired > 0 ? 0 : soon > 0 ? 0.5 : 1,
  });

  // HTTPS on proxy hosts.
  const tls = proxies.filter((h) => h.tls_mode !== "none").length;
  const tlsShare = proxies.length === 0 ? 1 : tls / proxies.length;
  checks.push({
    id: "tls",
    title: proxies.length === 0 ? "HTTPS: nothing to serve yet" : `HTTPS on ${tls} of ${proxies.length} proxy host${proxies.length === 1 ? "" : "s"}`,
    detail: tlsShare >= 1 ? "Every proxied host has a certificate" : "Plain-HTTP hosts send traffic in the clear",
    state: tlsShare >= 1 ? "pass" : tlsShare >= 0.5 ? "warn" : "fail",
    href: "/hosts",
    action: "Open hosts",
    names: proxies.filter((h) => h.tls_mode === "none").map((h) => h.domain_names[0] ?? "(unnamed)"),
    weight: 15,
    earned: tlsShare,
  });

  const total = checks.reduce((s, c) => s + c.weight, 0);
  const got = checks.reduce((s, c) => s + c.weight * c.earned, 0);
  return {
    score: Math.round((got / total) * 100),
    checks,
    issues: checks.filter((c) => c.state !== "pass").length,
  };
}
