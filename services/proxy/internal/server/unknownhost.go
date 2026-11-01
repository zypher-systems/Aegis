package server

import (
	"bytes"
	"errors"
	"log"
	"net/http"
)

// A name no enabled host is configured for is dropped by default: over HTTPS
// the handshake is cut before the proxy sends a byte, over plain HTTP the
// connection is closed (HTTP/2: the stream is reset) without a response. A
// scanner learns nothing, not even that this edge serves web traffic.
// AEGIS_UNKNOWN_HOST=page restores the placeholder certificate and the 404
// error page.
const (
	UnknownHostDrop = "drop"
	UnknownHostPage = "page"
)

// statusDropped is what the access log, metrics and telemetry record for a
// request dropped without a reply (nginx's 444).
const statusDropped = 444

// errUnknownServerName ends a TLS handshake for a name no host serves.
var errUnknownServerName = errors.New("aegis: dropped unknown server name")

// dropRequest ends the request with no response at all. net/http recovers
// ErrAbortHandler without logging it: HTTP/1 closes the connection with
// nothing written, HTTP/2 resets the stream.
func dropRequest(w http.ResponseWriter) {
	if sw, ok := w.(*statusWriter); ok {
		sw.code = statusDropped
	}
	panic(http.ErrAbortHandler)
}

// EdgeErrorLog is the error log for the edge http.Servers: the standard
// logger, minus the handshake failures of dropped unknown names, which every
// scanner would otherwise add a line for.
func EdgeErrorLog() *log.Logger {
	return log.New(quietDrops{}, "", 0)
}

type quietDrops struct{}

func (quietDrops) Write(p []byte) (int, error) {
	if !bytes.Contains(p, []byte(errUnknownServerName.Error())) {
		log.Print(string(p))
	}
	return len(p), nil
}
