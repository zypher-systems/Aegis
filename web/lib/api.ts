import type { AccessList, AccessListInput, AnalyticsEvent, AnalyticsSummary, AuditEvent, Certificate, CertificateStatus, CrowdSecAlert, CrowdSecDecisionPage, CrowdSecStatus, EnrollToken, EnrollTokenStatus, GeoRollupRow, Host, HostInput, Node, Notice, RequestLogPage, RollupRow, User, WAFFinding, WAFPackage, WAFProfile, WAFProfileInput, WAFRule } from "./types";

// Client-side fetch helpers. The browser calls same-origin /api/*, which
// Next.js rewrites to the control plane, so the session cookie flows through.
function csrfToken(): string {
  if (typeof document === "undefined") return "";
  const m = document.cookie.match(/(?:^|; )aegis_csrf=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : "";
}

type UnauthorizedHandler = () => void;
let unauthorizedHandler: UnauthorizedHandler | null = null;
let handlingUnauthorized = false;

export function setUnauthorizedHandler(fn: UnauthorizedHandler | null) {
  unauthorizedHandler = fn;
}

function authExempt(path: string): boolean {
  return (
    path === "/api/auth/login" ||
    path === "/api/auth/logout" ||
    path === "/api/setup" ||
    path === "/api/setup/status" ||
    path === "/api/me/password"
  );
}

function notifyUnauthorized(path: string) {
  if (authExempt(path) || handlingUnauthorized) return;
  handlingUnauthorized = true;
  try {
    unauthorizedHandler?.();
  } finally {
    setTimeout(() => {
      handlingUnauthorized = false;
    }, 500);
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  const tok = csrfToken();
  if (tok) headers["X-CSRF-Token"] = tok;
  const res = await fetch(path, {
    ...init,
    headers,
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = parseJSONBody(text, res.status);
  if (res.status === 401) notifyUnauthorized(path);
  // The CSRF check runs before authentication, so a request made after the
  // session cookie expired fails as "csrf: token mismatch". Tell them apart.
  if (res.status === 403 && /csrf/i.test(data?.error ?? "") && !authExempt(path)) {
    const me = await fetch("/api/me", { cache: "no-store" }).catch(() => null);
    if (me && me.status === 401) {
      notifyUnauthorized(path);
      throw new ApiError(401, "Session expired. Sign in again.");
    }
  }
  if (!res.ok) throw new ApiError(res.status, data?.error ?? res.statusText);
  return data as T;
}

function parseJSONBody(text: string, status: number): { error?: string } | null {
  if (!text) return null;
  try {
    return JSON.parse(text) as { error?: string };
  } catch {
    const snippet = text.replace(/\s+/g, " ").trim().slice(0, 160);
    throw new ApiError(
      status,
      snippet
        ? `non-JSON response (${status}): ${snippet}`
        : `empty non-JSON response (${status})`,
    );
  }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function isUnauthorized(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

/** Operator-facing copy for login/setup failures. Do not swallow CSRF as a down API. */
export function authFailureMessage(e: unknown, fallback: string): string {
  if (!(e instanceof ApiError)) {
    return fallback;
  }
  if (e.status === 401) {
    return "Invalid email or password.";
  }
  const msg = e.message || "";
  if (e.status === 403 && /csrf/i.test(msg)) {
    if (/origin/i.test(msg)) {
      return "This address is not allowed (CSRF). Open the dashboard at AEGIS_PUBLIC_ORIGIN. localhost and 127.0.0.1 count as the same host.";
    }
    return "Sign-in blocked by CSRF. Refresh the page and try again.";
  }
  if (e.status >= 500) {
    return fallback;
  }
  return msg || fallback;
}

// List endpoints: an empty collection must never reach a page as null (an
// API that encodes an empty Go slice as null would crash every .filter/.map).
function list<T>(path: string, init?: RequestInit): Promise<T[]> {
  return req<T[] | null>(path, init).then((v) => v ?? []);
}

export const api = {
  setupStatus: () => req<{ needs_setup: boolean }>("/api/setup/status"),
  setup: (email: string, name: string, password: string) =>
    req<User>("/api/setup", { method: "POST", body: JSON.stringify({ email, name, password }) }),
  login: (email: string, password: string) =>
    req<User>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => req<void>("/api/auth/logout", { method: "POST" }),
  me: () => req<User>("/api/me"),
  nodes: () => list<Node>("/api/nodes"),
  revokeNode: (id: string) => req<void>(`/api/nodes/${id}`, { method: "DELETE" }),
  hosts: () => list<Host>("/api/hosts"),
  createHost: (h: HostInput) => req<Host>("/api/hosts", { method: "POST", body: JSON.stringify(h) }),
  updateHost: (id: string, h: HostInput) =>
    req<Host>(`/api/hosts/${id}`, { method: "PUT", body: JSON.stringify(h) }),
  deleteHost: (id: string) => req<void>(`/api/hosts/${id}`, { method: "DELETE" }),
  bulkHosts: (input: { ids: string[]; action: "enable" | "disable" | "delete" | "set_access_list" | "set_waf_profile"; access_list_id?: string | null; waf_profile_id?: string | null }) =>
    req<{ done: number; failed: { id: string; error: string }[] }>("/api/hosts/bulk", { method: "POST", body: JSON.stringify(input) }),
  exportHostsURL: () => "/api/hosts/export",
  importHosts: (hosts: unknown[], mode: "skip" | "update") =>
    req<{ created: number; updated: number; skipped: number; problems: { domains: string[] | null; error: string }[] }>("/api/hosts/import", {
      method: "POST",
      body: JSON.stringify({ hosts, mode }),
    }),
  renameNode: (id: string, name: string) =>
    req<{ id: string; name: string }>(`/api/nodes/${id}`, { method: "PATCH", body: JSON.stringify({ name }) }),
  certificates: () => list<Certificate>("/api/certificates"),
  certificateStatus: () => req<CertificateStatus>("/api/certificates/status"),
  issueCertificate: (domains: string[]) =>
    req<Certificate>("/api/certificates/issue", {
      method: "POST",
      body: JSON.stringify({ domains }),
    }),
  uploadCertificate: (cert_pem: string, key_pem: string, chain_pem?: string) =>
    req<Certificate>("/api/certificates", {
      method: "POST",
      body: JSON.stringify({ cert_pem, key_pem, chain_pem: chain_pem || "" }),
    }),
  deleteCertificate: (id: string) => req<void>(`/api/certificates/${id}`, { method: "DELETE" }),
  renewCertificate: (id: string) => req<Certificate>(`/api/certificates/${id}/renew`, { method: "POST" }),
  setCertificateAutoRenew: (id: string, on: boolean) =>
    req<Certificate>(`/api/certificates/${id}`, { method: "PATCH", body: JSON.stringify({ auto_renew: on }) }),
  certificatePEMURL: (id: string) => `/api/certificates/${id}/pem`,
  certSettings: () => req<{ renew_before_days: number }>("/api/settings/certificates"),
  putCertSettings: (days: number) =>
    req<{ renew_before_days: number }>("/api/settings/certificates", { method: "PUT", body: JSON.stringify({ renew_before_days: days }) }),
  enrollTokenStatus: () => req<EnrollTokenStatus>("/api/settings/enroll-token"),
  enrollTokens: () => list<EnrollToken>("/api/settings/enroll-tokens"),
  createEnrollToken: (input: { label: string; ttl_minutes: number; uses: number }) =>
    req<{ token: string; meta: EnrollToken }>("/api/settings/enroll-tokens", { method: "POST", body: JSON.stringify(input) }),
  deleteEnrollToken: (id: string) => req<void>(`/api/settings/enroll-tokens/${id}`, { method: "DELETE" }),
  accessLists: () => list<AccessList>("/api/access-lists"),
  createAccessList: (a: AccessListInput) =>
    req<AccessList>("/api/access-lists", { method: "POST", body: JSON.stringify(a) }),
  updateAccessList: (id: string, a: AccessListInput) =>
    req<AccessList>(`/api/access-lists/${id}`, { method: "PUT", body: JSON.stringify(a) }),
  deleteAccessList: (id: string) => req<void>(`/api/access-lists/${id}`, { method: "DELETE" }),
  wafRules: () => list<WAFPackage>("/api/waf/rules"),
  wafCatalog: () => list<WAFRule>("/api/waf/catalog"),
  wafFindings: (opts?: { from?: string; host_id?: string }) => {
    const q = new URLSearchParams();
    if (opts?.from) q.set("from", opts.from);
    if (opts?.host_id) q.set("host_id", opts.host_id);
    const qs = q.toString();
    return req<{ rows: WAFFinding[] | null }>(`/api/analytics/waf-findings${qs ? `?${qs}` : ""}`).then((r) => r.rows ?? []);
  },
  wafProfiles: () => list<WAFProfile>("/api/waf-profiles"),
  createWAFProfile: (p: WAFProfileInput) =>
    req<WAFProfile>("/api/waf-profiles", { method: "POST", body: JSON.stringify(p) }),
  updateWAFProfile: (id: string, p: WAFProfileInput) =>
    req<WAFProfile>(`/api/waf-profiles/${id}`, { method: "PUT", body: JSON.stringify(p) }),
  deleteWAFProfile: (id: string) => req<void>(`/api/waf-profiles/${id}`, { method: "DELETE" }),
  users: () => list<User>("/api/users"),
  createUser: (email: string, name: string, password: string) =>
    req<User>("/api/users", { method: "POST", body: JSON.stringify({ email, name, password }) }),
  updateUser: (id: string, email: string, name: string, password?: string) =>
    req<User>(`/api/users/${id}`, { method: "PUT", body: JSON.stringify({ email, name, password: password || "" }) }),
  deleteUser: (id: string) => req<void>(`/api/users/${id}`, { method: "DELETE" }),
  revokeAllSessions: () => req<void>("/api/me/sessions/revoke-all", { method: "POST" }),
  changeMyPassword: (current: string, password: string) =>
    req<User>("/api/me/password", { method: "POST", body: JSON.stringify({ current, password }) }),
  audit: (limit = 50) => list<AuditEvent>(`/api/audit?limit=${limit}`),
  notices: () => list<Notice>("/api/notices"),
  dnsCloudflareStatus: () => req<{ configured: boolean }>("/api/settings/dns-cloudflare"),
  putDNSCloudflare: (token: string) =>
    req<{ configured: boolean }>("/api/settings/dns-cloudflare", {
      method: "PUT",
      body: JSON.stringify({ token }),
    }),
  healthz: () => req<{ status: string; version?: string }>("/api/healthz"),
  crowdsecStatus: () => req<CrowdSecStatus>("/api/settings/crowdsec"),
  putCrowdsecFirewall: (enabled: boolean) =>
    req<{ firewall_enabled: boolean; firewall_control: boolean }>("/api/settings/crowdsec/firewall", {
      method: "PUT",
      body: JSON.stringify({ enabled }),
    }),
  crowdsecDecisions: (p: { limit?: number; offset?: number; q?: string; origin?: string } = {}) => {
    const q = new URLSearchParams();
    if (p.limit) q.set("limit", String(p.limit));
    if (p.offset) q.set("offset", String(p.offset));
    if (p.q) q.set("q", p.q);
    if (p.origin) q.set("origin", p.origin);
    const qs = q.toString();
    return req<CrowdSecDecisionPage>(`/api/crowdsec/decisions${qs ? `?${qs}` : ""}`);
  },
  crowdsecAlerts: () => req<{ alerts: CrowdSecAlert[]; source: string }>("/api/crowdsec/alerts"),
  crowdsecBan: (body: { ip: string; duration: string; reason?: string }) =>
    req<{ ok: boolean; value: string; duration: string; firewall_enabled: boolean; warning?: string }>(
      "/api/crowdsec/decisions",
      { method: "POST", body: JSON.stringify(body) },
    ),
  crowdsecUnban: (id: number) =>
    req<{ ok: boolean }>("/api/crowdsec/decisions/" + id, { method: "DELETE" }),
  geoipStatus: () => req<{ configured: boolean; ready?: boolean; path: string }>("/api/settings/geoip"),
  alertsStatus: () => req<{ configured: boolean; hint: string }>("/api/settings/alerts"),
  putAlerts: (url: string) =>
    req<{ configured: boolean; hint: string }>("/api/settings/alerts", { method: "PUT", body: JSON.stringify({ url }) }),
  testAlerts: () => req<{ ok: boolean }>("/api/settings/alerts/test", { method: "POST" }),
  trustedProxyStatus: () => req<{ cidrs: string[] }>("/api/settings/trusted-proxy"),
  putTrustedProxy: (cidrs: string[]) =>
    req<{ cidrs: string[] }>("/api/settings/trusted-proxy", {
      method: "PUT",
      body: JSON.stringify({ cidrs }),
    }),
  telemetry: () => req<{ received: number }>("/api/telemetry"),
  analyticsLive: (limit = 50) =>
    req<{ events: AnalyticsEvent[] }>(`/api/analytics/live?limit=${limit}`),
  analyticsSummary: () => req<AnalyticsSummary>("/api/analytics/summary"),
  // Filters and cursor as in lib/requests.ts; empty values are dropped.
  analyticsRequests: (params: Record<string, string | number | undefined>) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") q.set(k, String(v));
    return req<RequestLogPage>(`/api/analytics/requests?${q.toString()}`).then((p) => ({ ...p, events: p.events ?? [] }));
  },
  // group "bucket" sums hosts away (one row per bucket, status class and
  // stage); "host" sums buckets away (per host, busiest first). truncated
  // means more rows matched than one response carries: the oldest buckets
  // (the quietest hosts for "host") are missing, not zero.
  analyticsRollups: (
    period: "hourly" | "daily" = "hourly",
    opts?: { from?: string; to?: string; host_id?: string; group?: "bucket" | "host" },
  ) => {
    const q = new URLSearchParams({ period });
    if (opts?.from) q.set("from", opts.from);
    if (opts?.to) q.set("to", opts.to);
    if (opts?.host_id) q.set("host_id", opts.host_id);
    if (opts?.group) q.set("group", opts.group);
    return req<{ rows: RollupRow[]; truncated?: boolean }>(`/api/analytics/rollups?${q.toString()}`);
  },
  analyticsGeo: (period: "hourly" | "daily" = "hourly", opts?: { from?: string; to?: string; host_id?: string }) => {
    const q = new URLSearchParams({ period });
    if (opts?.from) q.set("from", opts.from);
    if (opts?.to) q.set("to", opts.to);
    if (opts?.host_id) q.set("host_id", opts.host_id);
    return req<{ rows: GeoRollupRow[] }>(`/api/analytics/geo?${q.toString()}`);
  },
};
