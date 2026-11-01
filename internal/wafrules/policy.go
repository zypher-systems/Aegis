package wafrules

import (
	"regexp"
	"sort"
	"strings"
)

// Protocol policy. CRS ships defaults for a classic form-posting web app
// (GET/HEAD/POST/OPTIONS, six content types, a list of restricted headers
// that includes Expect and Content-Encoding). Those block every REST API,
// SPA and SDK before an attack rule ever runs, so Aegis ships wider defaults
// and lets a profile edit them in plain terms.

// DefaultAllowedMethods covers REST APIs. WebDAVMethods is the preset for
// Nextcloud, calendars and other DAV apps.
var (
	DefaultAllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	WebDAVMethods         = []string{"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH"}
)

// DefaultAllowedContentTypes is CRS's list plus what browsers, SDKs and APIs
// send today. An empty profile list means this one; AnyContentType turns
// the check off.
var DefaultAllowedContentTypes = []string{
	"application/x-www-form-urlencoded", "multipart/form-data", "multipart/related",
	"text/xml", "application/xml", "application/soap+xml",
	"application/json", "application/vnd.api+json", "application/merge-patch+json", "application/json-patch+json",
	"application/x-ndjson", "application/graphql", "application/graphql-response+json",
	"application/csp-report", "application/reports+json",
	"text/plain", "text/csv", "application/octet-stream",
	"application/grpc", "application/grpc-web", "application/grpc-web+proto", "application/x-protobuf",
	"application/msgpack", "application/cbor",
	"application/pdf", "application/zip", "application/gzip",
	"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml",
}

// CRSRestrictedHeaders is CRS's PL1 list (rule 920450). A profile's
// RestrictedHeaders replaces it; empty means DefaultRestrictedHeaders, which
// is that list without the three that ordinary clients send (Expect on big
// uploads, Content-Encoding on compressed bodies, Content-Range on resumable
// uploads).
var (
	CRSRestrictedHeaders = []string{"content-encoding", "proxy", "lock-token", "content-range", "if",
		"x-http-method-override", "x-http-method", "x-method-override", "x-middleware-subrequest", "expect"}
	DefaultRestrictedHeaders = []string{"proxy", "lock-token", "if", "x-http-method-override", "x-http-method",
		"x-method-override", "x-middleware-subrequest"}
)

var (
	methodRe      = regexp.MustCompile(`^[A-Z][A-Z-]{1,19}$`)
	contentTypeRe = regexp.MustCompile(`^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$`)
	headerNameRe  = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
)

// NormalizeMethods upper-cases, validates and de-duplicates; an empty
// result means the default list.
func NormalizeMethods(in []string) []string {
	out := dedupe(in, strings.ToUpper, methodRe)
	if len(out) == 0 {
		return append([]string(nil), DefaultAllowedMethods...)
	}
	return out
}

// NormalizeContentTypes lower-cases, validates and de-duplicates. Empty
// stays empty (= the default list).
func NormalizeContentTypes(in []string) []string {
	return dedupe(in, strings.ToLower, contentTypeRe)
}

// NormalizeHeaders lower-cases, validates and de-duplicates header names.
// Empty stays empty (= the default restricted list).
func NormalizeHeaders(in []string) []string {
	return dedupe(in, strings.ToLower, headerNameRe)
}

func dedupe(in []string, norm func(string) string, re *regexp.Regexp) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = norm(strings.TrimSpace(v))
		if v == "" || !re.MatchString(v) || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// MethodsSecLang is the value for tx.allowed_methods.
func MethodsSecLang(methods []string) string {
	return strings.Join(NormalizeMethods(methods), " ")
}

// ContentTypesSecLang is the value for tx.allowed_request_content_type:
// "|a| |b|" as CRS 4 expects.
func ContentTypesSecLang(types []string) string {
	ts := NormalizeContentTypes(types)
	if len(ts) == 0 {
		ts = DefaultAllowedContentTypes
	}
	parts := make([]string, 0, len(ts))
	for _, t := range ts {
		parts = append(parts, "|"+t+"|")
	}
	return strings.Join(parts, " ")
}

// RestrictedHeadersSecLang is the value for tx.restricted_headers_basic:
// "/a/ /b/". CRS matches it with @within, so an empty value would restrict
// nothing; a profile that restricts no header at all gets a placeholder that
// no real header name can match.
func RestrictedHeadersSecLang(restricted []string) string {
	hs := NormalizeHeaders(restricted)
	if len(hs) == 0 {
		hs = DefaultRestrictedHeaders
	}
	parts := make([]string, 0, len(hs))
	for _, h := range hs {
		parts = append(parts, "/"+h+"/")
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}
