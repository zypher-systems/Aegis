// Mirrors internal/wafrules/policy.go so the dialog can show what "default"
// means without a round trip.
export const DEFAULT_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
export const WEBDAV_METHODS = ["PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH"];
export const ALL_METHODS = [...DEFAULT_METHODS, ...WEBDAV_METHODS, "TRACE", "CONNECT"];

export const CRS_RESTRICTED_HEADERS: { name: string; why: string; defaultOn: boolean }[] = [
  { name: "expect", why: "curl, SDKs and some browsers send Expect: 100-continue on uploads over 1 MB", defaultOn: false },
  { name: "content-encoding", why: "compressed request bodies (gzip) from SDKs and telemetry agents", defaultOn: false },
  { name: "content-range", why: "resumable and chunked uploads", defaultOn: false },
  { name: "x-http-method-override", why: "lets a POST act as PUT/DELETE; keep restricted unless the app needs it", defaultOn: true },
  { name: "x-http-method", why: "same as above (older name)", defaultOn: true },
  { name: "x-method-override", why: "same as above (older name)", defaultOn: true },
  { name: "x-middleware-subrequest", why: "Next.js internal header that bypassed middleware (CVE-2025-29927)", defaultOn: true },
  { name: "proxy", why: "the httpoxy header; no client should send it", defaultOn: true },
  { name: "lock-token", why: "WebDAV locking; allow for DAV apps", defaultOn: true },
  { name: "if", why: "WebDAV conditional header; allow for DAV apps", defaultOn: true },
];
export const DEFAULT_RESTRICTED_HEADERS = CRS_RESTRICTED_HEADERS.filter((h) => h.defaultOn).map((h) => h.name);

export const DEFAULT_CONTENT_TYPES_SUMMARY =
  "forms, multipart, JSON (all common variants), XML/SOAP, GraphQL, NDJSON, text/plain, CSV, octet-stream, gRPC/protobuf, msgpack, CBOR, PDF, zip/gzip and common image types";

// Rules whose right fix is the protocol policy, not an exclusion.
export const POLICY_RULES: Record<string, string> = {
  "911100": "allowed methods",
  "920420": "request content types",
  "920450": "restricted request headers",
};

// Collections an exclusion's "Only this input" can name (matches
// internal/wafrules/exclusion.go); REQUEST_METHOD, REQUEST_FILENAME and
// the like can only be excluded by path or everywhere.
const EXCLUDABLE = new Set(["ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES", "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES", "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES", "XML"]);
export function excludableInput(where: string) {
  return EXCLUDABLE.has(where.split(":")[0]);
}

export function sameSet(a: string[], b: string[]) {
  const sa = new Set(a.map((x) => x.toLowerCase()));
  const sb = new Set(b.map((x) => x.toLowerCase()));
  return sa.size === sb.size && [...sa].every((x) => sb.has(x));
}
