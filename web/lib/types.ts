export type User = { id: string; email: string; name: string; role: string };

export type AuditEvent = {
  id: string;
  at: string;
  actor_id?: string;
  actor_email: string;
  action: string;
  resource_type: string;
  resource_id: string;
  summary: Record<string, unknown>;
};

export type Notice = {
  kind: string;
  resource_id: string;
  title: string;
  detail: string;
  next_attempt?: string;
  at: string;
};

export type HostKind = "proxy" | "redirect" | "dead" | "stream";

export type HostUpstream = {
  scheme: string;
  host: string;
  port: number;
  tls_skip_verify?: boolean;
  tls_server_name?: string;
  tls_ca_pem?: string;
  // Share under round_robin; 0 or missing = 1.
  weight?: number;
};

export type Host = {
  id: string;
  kind: HostKind;
  domain_names: string[];
  upstream_scheme: string;
  upstream_host: string;
  upstream_port: number;
  upstreams?: HostUpstream[];
  // "" = client's Host (default), "upstream" = upstream host:port, else literal.
  upstream_host_header?: string;
  // "" | "failover" (first healthy in order) | "round_robin" (weighted).
  lb_policy?: string;
  // HTTP path probed on each upstream; "" = TCP connect check.
  health_path?: string;
  // Timeouts and limits; 0 = default (60 s, 60 s, no body limit).
  idle_timeout_seconds?: number;
  upstream_response_timeout_seconds?: number;
  max_body_bytes?: number;
  enabled: boolean;
  tls_mode: "auto" | "custom" | "none";
  cert_id?: string;
  force_https: boolean;
  hsts: boolean;
  hsts_max_age?: number;
  hsts_subdomains?: boolean;
  hsts_preload?: boolean;
  websocket_support: boolean;
  redirect_url: string;
  redirect_code: number;
  request_headers: Record<string, string>;
  response_headers: Record<string, string>;
  access_list_id?: string;
  listen_protocol: string;
  listen_port: number;
  waf_profile_id?: string;
  rate_limit_rps: number;
  rate_limit_burst: number;
  geo_allow: string[];
  geo_deny: string[];
  crowdsec_enabled: boolean;
  oidc: HostOIDC;
  created_at: string;
  updated_at: string;
};

export type HostOIDC = {
  enabled: boolean;
  issuer: string;
  client_id: string;
  client_secret: string;
  paths: string[];
  cookie_name: string;
};

export type HostInput = {
  kind: HostKind;
  domain_names: string[];
  upstream_scheme: string;
  upstream_host: string;
  upstream_port: number;
  upstreams?: HostUpstream[];
  // "" = client's Host (default), "upstream" = upstream host:port, else literal.
  upstream_host_header?: string;
  lb_policy?: string;
  health_path?: string;
  idle_timeout_seconds?: number;
  upstream_response_timeout_seconds?: number;
  max_body_bytes?: number;
  enabled: boolean;
  tls_mode: "auto" | "custom" | "none";
  cert_id?: string;
  force_https: boolean;
  hsts: boolean;
  hsts_max_age?: number;
  hsts_subdomains?: boolean;
  hsts_preload?: boolean;
  websocket_support: boolean;
  redirect_url?: string;
  redirect_code?: number;
  request_headers?: Record<string, string>;
  response_headers?: Record<string, string>;
  access_list_id?: string;
  listen_protocol?: string;
  listen_port?: number;
  waf_profile_id?: string;
  rate_limit_rps?: number;
  rate_limit_burst?: number;
  geo_allow?: string[];
  geo_deny?: string[];
  crowdsec_enabled?: boolean;
  oidc?: HostOIDC;
};

export type WAFPackage = {
  tag: string;
  name: string;
  description: string;
};

export type WAFExclusion = {
  rule_id: string;
  // Optional path prefix; empty = every path.
  path?: string;
  // Optional input the rule stops inspecting (REQUEST_COOKIES:name, ARGS:q,
  // COLLECTION:/regex/); empty = the whole rule is off.
  target?: string;
};

export type WAFProfile = {
  id: string;
  name: string;
  mode: "detect" | "block";
  paranoia: number;
  inbound_threshold: number;
  // How much of a request body is inspected; the rest is forwarded. 0 = 1 MiB.
  body_limit_bytes?: number;
  // Protocol policy. Empty lists mean the Aegis defaults.
  allowed_methods?: string[];
  allowed_content_types?: string[];
  any_content_type?: boolean;
  restricted_headers?: string[];
  disabled_tags: string[];
  exclusions: WAFExclusion[];
  created_at: string;
  updated_at: string;
};

// One CRS rule from GET /api/waf/catalog.
export type WAFRule = {
  id: string;
  message: string;
  severity?: string;
  paranoia?: number;
  category: string;
};

// One row of GET /api/analytics/waf-findings: a rule's hits with a sample.
export type EnrollToken = {
  id: string;
  label: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  uses_left: number;
};

export type EnrollTokenStatus = { bootstrap_accepted: boolean; nodes: number; live_tokens: number };

export type WAFFinding = {
  rule_id: string;
  message: string;
  category: string;
  paranoia: number;
  hits: number;
  blocked: number;
  clients: number;
  first_seen: string;
  last_seen: string;
  hosts: string[];
  paths: string[];
  sample_where: string;
  sample_value: string;
  host_id: string;
  path: string;
};

export type WAFProfileInput = {
  name: string;
  mode: "detect" | "block";
  paranoia: number;
  inbound_threshold: number;
  body_limit_bytes?: number;
  allowed_methods?: string[];
  allowed_content_types?: string[];
  any_content_type?: boolean;
  restricted_headers?: string[];
  disabled_tags: string[];
  exclusions: WAFExclusion[];
};

export type AccessListUser = {
  username: string;
  password_hash?: string;
  password?: string;
};

export type AccessList = {
  id: string;
  name: string;
  satisfy: "any" | "all";
  users: AccessListUser[];
  allow_cidrs: string[];
  deny_cidrs: string[];
  created_at: string;
  updated_at: string;
};

export type AccessListInput = {
  name: string;
  satisfy: "any" | "all";
  users: { username: string; password?: string }[];
  allow_cidrs: string[];
  deny_cidrs: string[];
};

export type Certificate = {
  id: string;
  domains: string[];
  issuer: "letsencrypt" | "selfsigned" | "custom" | string;
  expires_at: string;
  created_at?: string;
  auto_renew?: boolean;
  acme_directory?: string;
  // Present when the last renewal attempt failed.
  renewal?: { failing: boolean; fails?: number; next_attempt?: string };
};

export type CertificateStatus = {
  self_signed: boolean;
  acme_email: boolean;
};

export type Node = {
  id: string;
  name: string;
  agent_version: string;
  cert_expires_at: string;
  last_seen_at?: string;
  revoked_at?: string;
  created_at: string;
  online?: boolean;
  revoked?: boolean;
  rps?: number;
  p50_ms?: number;
  p99_ms?: number;
  requests?: number;
};

export type AnalyticsEvent = {
  timestamp_unix_ms: number;
  host_id: string;
  node_id: string;
  domain: string;
  method: string;
  path: string;
  status: number;
  duration_ms: number;
  client_ip: string;
  user_agent: string;
  bytes_sent: number;
  country?: string;
  waf_action?: string;
  waf_rule_id?: string;
  waf_score?: number;
  block_stage?: string;
  crowdsec_origin?: string;
  // Request detail, from nodes on 1.7.1 or later.
  id?: string;
  query?: string;
  referer?: string;
  protocol?: string;
  scheme?: string;
  tls_version?: string;
  upstream?: string;
  peer_ip?: string;
  bytes_received?: number;
  block_detail?: string;
  waf_matches?: WAFMatch[];
};

// One CRS rule that matched a request. severity: 2 critical … 5 notice.
export type WAFMatch = {
  rule_id: string;
  message: string;
  severity: number;
  variable?: string;
  key?: string;
  value?: string;
};

// GET /api/analytics/requests: one page of the request log, newest first.
export type RequestLogPage = {
  events: AnalyticsEvent[];
  next: string;
  count: number;
  count_capped: boolean;
  log_mode: "all" | "security" | "off";
};

export type AnalyticsSummary = {
  received: number;
  window_events: number;
  blocked: number;
  p50_ms: number;
  p99_ms: number;
  rps: number;
  histogram: { le: number; count: number }[];
  top_paths: { key: string; count: number }[];
  top_clients: { key: string; count: number }[];
  geo: { key: string; count: number }[];
  blocked_by_stage: { key: string; count: number }[];
};

export type GeoRollupRow = {
  bucket_start: string;
  host_id: string;
  country: string;
  count: number;
};

export type RollupRow = {
  bucket_start: string;
  host_id: string;
  domain: string;
  status_class: number;
  block_stage: string;
  count: number;
  latency_sum_ms: number;
  bytes_sum: number;
};

export type CrowdSecStatus = {
  configured: boolean;
  url: string;
  in_stack?: boolean;
  lapi_ok?: boolean;
  error?: string;
  firewall_enabled?: boolean;
  firewall_control?: boolean;
  can_ban?: boolean;
};

export type CrowdSecDecision = {
  id: number;
  origin: string;
  scenario: string;
  scope: string;
  type: string;
  value: string;
  duration: string;
};
// GET /api/crowdsec/decisions: one server-side page, newest first.
// by_origin counts every decision matching q, ignoring the origin filter.
export type CrowdSecDecisionPage = {
  decisions: CrowdSecDecision[];
  total: number;
  by_origin: Record<string, number>;
  limit?: number;
  offset?: number;
  configured: boolean;
};

export type CrowdSecAlert = {
  timestamp_unix_ms: number;
  domain: string;
  client_ip: string;
  path: string;
  origin: string;
  status: number;
};
