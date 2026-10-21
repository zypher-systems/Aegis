package server

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Error responses the proxy writes itself (a blocked request, an unknown
// host, an upstream that is down) get a small page with the status, a plain
// sentence and the request ID, so a visitor can quote something useful and
// an operator can find the request in Analytics. Browsers get HTML, anything
// else gets one line of text. AEGIS_ERROR_PAGE names an operator template
// (html/template; fields Status, Title, Message, RequestID, Host, Time).

type errorPageData struct {
	Status    int
	Title     string
	Message   string
	RequestID string
	Host      string
	Time      string
}

var errorTemplate atomic.Pointer[template.Template]

const defaultErrorPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Status}} {{.Title}}</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0c0d0f;color:#ececef}
main{max-width:34rem;padding:2rem 1.25rem;text-align:center}
.code{font-size:.8rem;letter-spacing:.2em;text-transform:uppercase;color:#6c9dff;font-weight:700}
h1{font-size:1.6rem;margin:.5rem 0 .75rem}
p{margin:0 0 1rem;opacity:.8}
.ref{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;opacity:.6;word-break:break-all}
@media (prefers-color-scheme:light){body{background:#f5f6f8;color:#111317}.code{color:#1f5bd8}}
</style></head>
<body><main>
<div class="code">{{.Status}}</div>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
{{if .RequestID}}<div class="ref">Request {{.RequestID}} · {{.Time}}</div>{{end}}
</main></body></html>
`

func init() {
	errorTemplate.Store(mustDefault())
}

func mustDefault() *template.Template {
	return template.Must(template.New("error").Parse(defaultErrorPage))
}

// LoadErrorPage installs an operator template from path; on any problem the
// built-in page stays and the error is logged.
func LoadErrorPage(path string) {
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("proxy: error page %s: %v (using the built-in page)", path, err)
		return
	}
	t, err := template.New("error").Parse(string(b))
	if err != nil {
		log.Printf("proxy: error page %s: %v (using the built-in page)", path, err)
		return
	}
	// Render once so a template that references a missing field fails now.
	if err := t.Execute(new(strings.Builder), errorPageData{Status: 500, Title: "t", Message: "m"}); err != nil {
		log.Printf("proxy: error page %s: %v (using the built-in page)", path, err)
		return
	}
	errorTemplate.Store(t)
	log.Printf("proxy: error page from %s", path)
}

// errorText maps a status to what the visitor is told. Blocks are all
// described the same way on purpose: the page must not say which layer
// stopped the request or why.
func errorText(status int) (title, message string) {
	switch status {
	case http.StatusUnauthorized:
		return "Sign-in required", "This site asks for a username and password."
	case http.StatusForbidden:
		return "Request blocked", "This request was not allowed through. If you believe this is a mistake, contact the site owner and quote the request reference below."
	case http.StatusNotFound:
		return "No such site here", "Nothing is configured for this address."
	case http.StatusRequestEntityTooLarge:
		return "Upload too large", "The request body is bigger than this site accepts."
	case http.StatusTooManyRequests:
		return "Slow down", "Too many requests from your address in a short time. Wait a moment and try again."
	case http.StatusBadGateway:
		return "Site unavailable", "The application behind this address is not answering. It is usually back within a minute."
	case http.StatusServiceUnavailable:
		return "Temporarily unavailable", "This edge cannot serve the site right now. Please try again shortly."
	case http.StatusGatewayTimeout:
		return "Site too slow to answer", "The application behind this address took too long to respond."
	case statusClientClosed:
		return "Request cancelled", "The connection was closed before the response was ready."
	default:
		return http.StatusText(status), "The request could not be completed."
	}
}

// wantsHTML: a browser navigation rather than an API call or a script.
func wantsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml") {
		return true
	}
	return r.Header.Get("Sec-Fetch-Mode") == "navigate"
}

// writeError answers with the error page for status. Headers already set on
// w (Retry-After, WWW-Authenticate) are kept.
func writeError(w http.ResponseWriter, r *http.Request, status int) {
	title, message := errorText(status)
	id := ""
	if m := blockMetaFrom(r); m != nil {
		id = m.RequestID
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if wantsHTML(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = errorTemplate.Load().Execute(w, errorPageData{
			Status: status, Title: title, Message: message, RequestID: id,
			Host: r.Host, Time: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	if id != "" {
		fmt.Fprintf(w, "%d %s\nRequest %s\n", status, title, id)
		return
	}
	fmt.Fprintf(w, "%d %s\n", status, title)
}
