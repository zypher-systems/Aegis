// Package healthcheck is a distroless-friendly HTTP probe used as
// `aegis-api healthcheck` / `aegis-proxy healthcheck` from compose.
package healthcheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// URL builds an http URL for a probe against listenAddr (e.g. ":8080").
// Wildcard and unspecified hosts are rewritten to 127.0.0.1 so the probe
// stays on loopback inside the container.
func URL(listenAddr, path string) (string, error) {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("listen addr %q: %w", listenAddr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "http://" + net.JoinHostPort(host, port) + path, nil
}

// Probe GETs the URL derived from listenAddr+path and requires HTTP 200.
func Probe(listenAddr, path string) error {
	u, err := URL(listenAddr, path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", u, resp.StatusCode)
	}
	return nil
}

// Exit runs Probe and os.Exits 0 or 1. For container HEALTHCHECK CMD.
func Exit(listenAddr, path string) {
	if err := Probe(listenAddr, path); err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		os.Exit(1)
	}
	os.Exit(0)
}
