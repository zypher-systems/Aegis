package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

// edge serves s on a real plain-HTTP and TLS listener, as main does.
func edge(t *testing.T, s *Server) (plain, secure string) {
	t.Helper()
	serve := func(ln net.Listener) {
		srv := &http.Server{Handler: s, ErrorLog: EdgeErrorLog(), ReadHeaderTimeout: 5 * time.Second}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(ln)
	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serve(tls.NewListener(tln, s.TLSConfig()))
	return ln.Addr().String(), tln.Addr().String()
}

// countingConn counts the bytes the server sends.
type countingConn struct {
	net.Conn
	n int
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n += n
	return n, err
}

// rawGet sends one HTTP/1.1 request on conn and returns all the server sends
// back until it closes.
func rawGet(t *testing.T, conn net.Conn, host, path string) string {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("connection for %s%s left open instead of closed", host, path)
	}
	return string(b)
}

func dropConfig() *aegisv1.ConfigUpdate {
	return &aegisv1.ConfigUpdate{
		Version: 1,
		Hosts: []*aegisv1.Host{{
			Id: "d", DomainNames: []string{"known.local"}, Enabled: true,
			Kind: aegisv1.HostKind_HOST_KIND_DEAD,
		}},
		Challenges: []*aegisv1.Challenge{{Token: "tok", KeyAuthorization: "tok.ka"}},
	}
}

func TestUnknownHostDroppedOverHTTP(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "access.log")
	s := NewWithOptions(Options{AccessLog: logPath})
	s.Apply(dropConfig())
	plain, _ := edge(t, s)
	get := func(host, path string) string {
		conn, err := net.Dial("tcp", plain)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return rawGet(t, conn, host, path)
	}

	for _, c := range []struct{ host, path string }{
		{"nothing.example", "/"},
		{"203.0.113.1", "/"},
		{"nothing.example", "/.well-known/acme-challenge/unknown"},
	} {
		if got := get(c.host, c.path); got != "" {
			t.Fatalf("%s%s: want no reply, got %q", c.host, c.path, got)
		}
	}
	// Configured hosts and pending ACME tokens are answered as before.
	if got := get("known.local", "/"); !strings.HasPrefix(got, "HTTP/1.1 404") {
		t.Fatalf("known host: %q", got)
	}
	if got := get("known.local", "/.well-known/acme-challenge/unknown"); !strings.HasPrefix(got, "HTTP/1.1 404") {
		t.Fatalf("known host, unknown token: %q", got)
	}
	if got := get("nothing.example", "/.well-known/acme-challenge/tok"); !strings.HasSuffix(got, "\r\n\r\ntok.ka") {
		t.Fatalf("pending token: %q", got)
	}

	// The drop is still logged, as 444.
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var dropped int
	for sc := bufio.NewScanner(f); sc.Scan(); {
		if strings.Contains(sc.Text(), `HTTP/1.1" 444 0 `) {
			dropped++
		}
	}
	if dropped != 3 {
		t.Fatalf("access log has %d dropped requests, want 3", dropped)
	}
}

// tlsDial runs a client handshake with cfg against addr, counting the bytes
// the server sends.
func tlsDial(t *testing.T, addr string, cfg *tls.Config) (*tls.Conn, *countingConn, error) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	cc := &countingConn{Conn: raw}
	conn := tls.Client(cc, cfg)
	return conn, cc, conn.Handshake()
}

// assertSilent fails unless the handshake failed with the connection closed
// and not a byte from the server.
func assertSilent(t *testing.T, what string, cc *countingConn, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: handshake succeeded", what)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("%s: connection left open: %v", what, err)
	}
	if cc.n != 0 {
		t.Fatalf("%s: server sent %d bytes, want none", what, cc.n)
	}
}

func clientConfig(sni string) *tls.Config {
	return &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
}

func TestUnknownServerNameDroppedInHandshake(t *testing.T) {
	s := New()
	s.Apply(dropConfig())
	_, secure := edge(t, s)

	// Unknown SNI, and none at all (a bare-IP probe): not a byte back.
	for _, sni := range []string{"nothing.example", ""} {
		_, cc, err := tlsDial(t, secure, clientConfig(sni))
		assertSilent(t, fmt.Sprintf("%q", sni), cc, err)
	}

	// A configured host without a certificate yet still gets the placeholder,
	// and the request on it is routed. An unknown Host on that connection
	// (a client reusing it for another name) is dropped.
	conn, _, err := tlsDial(t, secure, clientConfig("known.local"))
	if err != nil {
		t.Fatalf("known host handshake: %v", err)
	}
	if cn := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "aegis-edge" {
		t.Fatalf("known host without cert: CN=%q, want the placeholder", cn)
	}
	if got := rawGet(t, conn, "known.local", "/"); !strings.HasPrefix(got, "HTTP/1.1 404") {
		t.Fatalf("known host over TLS: %q", got)
	}
	conn, _, err = tlsDial(t, secure, clientConfig("known.local"))
	if err != nil {
		t.Fatal(err)
	}
	if got := rawGet(t, conn, "nothing.example", "/"); got != "" {
		t.Fatalf("unknown Host over TLS: want no reply, got %q", got)
	}
}

// crypto/tls can answer a ClientHello before it asks for a certificate: an
// ALPN mismatch alert, or a HelloRetryRequest for a group the client listed
// without a key share. Neither may reach a client asking for an unknown name.
func TestUnknownServerNameSilentBeforeNegotiation(t *testing.T) {
	s := New()
	s.Apply(dropConfig())
	_, secure := edge(t, s)

	hrr := func(sni string) *tls.Config {
		c := clientConfig(sni)
		c.MinVersion = tls.VersionTLS13
		// Key share for P-256 only; the server prefers the hybrid group.
		c.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.X25519MLKEM768}
		return c
	}
	// The control: a known name takes the HelloRetryRequest path.
	conn, _, err := tlsDial(t, secure, hrr("known.local"))
	if err != nil {
		t.Fatalf("known host after HelloRetryRequest: %v", err)
	}
	if got := conn.ConnectionState().CurveID; got != tls.X25519MLKEM768 {
		t.Fatalf("control did not retry for the hybrid group (curve %v)", got)
	}

	for _, c := range []struct {
		what string
		cfg  *tls.Config
	}{
		{"unknown SNI, foreign ALPN", &tls.Config{ServerName: "nothing.example", InsecureSkipVerify: true, NextProtos: []string{"h3"}}},
		{"no SNI, foreign ALPN", &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}},
		{"unknown SNI, foreign ALPN, TLS 1.2", &tls.Config{ServerName: "nothing.example", InsecureSkipVerify: true, NextProtos: []string{"h3"}, MaxVersion: tls.VersionTLS12}},
		{"unknown SNI, HelloRetryRequest", hrr("nothing.example")},
		{"no SNI, HelloRetryRequest", hrr("")},
	} {
		_, cc, err := tlsDial(t, secure, c.cfg)
		assertSilent(t, c.what, cc, err)
	}
}

// anyNameCache hands the last session ticket to every server name, as a
// client replaying a ticket under another SNI would.
type anyNameCache struct {
	mu   sync.Mutex
	last *tls.ClientSessionState
}

func (c *anyNameCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.last != nil
}

func (c *anyNameCache) Put(_ string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cs != nil {
		c.last = cs
	}
}

// A TLS 1.3 resumption skips certificate selection, so it must not get past
// the name check either.
func TestSessionResumptionDoesNotBypassUnknownName(t *testing.T) {
	s := New()
	s.Apply(dropConfig())
	_, secure := edge(t, s)
	cache := &anyNameCache{}
	resuming := func(sni string) *tls.Config {
		c := clientConfig(sni)
		c.ClientSessionCache = cache
		return c
	}

	// Get a ticket from a configured host (it arrives with the response).
	conn, _, err := tlsDial(t, secure, resuming("known.local"))
	if err != nil {
		t.Fatal(err)
	}
	rawGet(t, conn, "known.local", "/")
	// The control: the ticket resumes for the name it was issued to.
	conn, _, err = tlsDial(t, secure, resuming("known.local"))
	if err != nil || !conn.ConnectionState().DidResume {
		t.Fatalf("control did not resume: %v", err)
	}
	rawGet(t, conn, "known.local", "/")

	_, cc, err := tlsDial(t, secure, resuming("nothing.example"))
	assertSilent(t, "ticket under an unknown SNI", cc, err)

	// The host is removed: its own ticket no longer opens a connection.
	s.Apply(&aegisv1.ConfigUpdate{Version: 2})
	_, cc, err = tlsDial(t, secure, resuming("known.local"))
	assertSilent(t, "ticket for a removed host", cc, err)
}

func TestEdgeErrorLogHidesOnlyDroppedNames(t *testing.T) {
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })

	l := EdgeErrorLog()
	l.Printf("http: TLS handshake error from 203.0.113.1:5: %v", errUnknownServerName)
	l.Printf("http: TLS handshake error from 203.0.113.1:6: EOF")
	if got := buf.String(); got != "http: TLS handshake error from 203.0.113.1:6: EOF\n" {
		t.Fatalf("log = %q", got)
	}
}
