package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func hostPort(t *testing.T, srv *httptest.Server) (string, uint32) {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	h, p, _ := net.SplitHostPort(u.Host)
	n, _ := strconv.Atoi(p)
	return h, uint32(n)
}

// deadPort is a closed port on loopback (connection refused).
func deadPort(t *testing.T) uint32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := uint32(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	return p
}

func applyTwoUpstreams(s *Server, id string, primary, backup *aegisv1.UpstreamTarget) {
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: id, DomainNames: []string{id + ".example.com"}, Enabled: true,
		UpstreamScheme: primary.Scheme, UpstreamHost: primary.Host, UpstreamPort: primary.Port,
		Upstreams: []*aegisv1.UpstreamTarget{primary, backup},
	}}})
}

func TestFailoverReplaysSmallBodyOnConnectFailure(t *testing.T) {
	var got atomic.Value
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(string(b))
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(backup.Close)
	bh, bp := hostPort(t, backup)
	s := New()
	applyTwoUpstreams(s, "fo",
		&aegisv1.UpstreamTarget{Scheme: "http", Host: "127.0.0.1", Port: deadPort(t)},
		&aegisv1.UpstreamTarget{Scheme: "http", Host: bh, Port: bp})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://fo.example.com/orders", strings.NewReader(`{"sku":"A1"}`))
	req.Host = "fo.example.com"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated || got.Load() != `{"sku":"A1"}` {
		t.Fatalf("status %d body %v: a POST whose primary refused the connection must reach the backup intact", rr.Code, got.Load())
	}
	if first := s.pools.order("fo")[0]; first.port != bp {
		t.Fatal("the refused primary must be marked down so the backup is tried first")
	}
}

func TestFailoverNeverReplaysAfterUpstreamAccepted(t *testing.T) {
	// Primary accepts the connection, reads the request, then drops it
	// (the app may have processed it). Backup counts what it receives.
	primary, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { primary.Close() })
	go func() {
		for {
			c, err := primary.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			c.Close()
		}
	}()
	var hits atomic.Int32
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backup.Close)
	bh, bp := hostPort(t, backup)
	s := New()
	applyTwoUpstreams(s, "acc",
		&aegisv1.UpstreamTarget{Scheme: "http", Host: "127.0.0.1", Port: uint32(primary.Addr().(*net.TCPAddr).Port)},
		&aegisv1.UpstreamTarget{Scheme: "http", Host: bh, Port: bp})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://acc.example.com/pay", strings.NewReader("amount=100"))
	req.Host = "acc.example.com"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rr.Code)
	}
	if hits.Load() != 0 {
		t.Fatal("a request the primary accepted must not be replayed to the backup")
	}
	if first := s.pools.order("acc")[0]; first.port == bp {
		t.Fatal("an upstream that accepts connections is not down; it must not be marked down")
	}
}

func TestFailoverSkipsReplayForLargeBodies(t *testing.T) {
	var hits atomic.Int32
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backup.Close)
	bh, bp := hostPort(t, backup)
	s := New()
	applyTwoUpstreams(s, "big",
		&aegisv1.UpstreamTarget{Scheme: "http", Host: "127.0.0.1", Port: deadPort(t)},
		&aegisv1.UpstreamTarget{Scheme: "http", Host: bh, Port: bp})
	body := strings.Repeat("x", retryBodyMax+1)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://big.example.com/upload", strings.NewReader(body))
	req.Host = "big.example.com"
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway || hits.Load() != 0 {
		t.Fatalf("status %d hits %d: a body over %d bytes is sent once and not replayed", rr.Code, hits.Load(), retryBodyMax)
	}
}

func TestMaxBodyBytesRejectsWith413(t *testing.T) {
	var hits atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	h, p := hostPort(t, up)
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: "cap", DomainNames: []string{"cap.example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: h, UpstreamPort: p, MaxBodyBytes: 1024,
	}}})
	do := func(body io.Reader, chunked bool) int {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://cap.example.com/", body)
		req.Host = "cap.example.com"
		if chunked {
			req.ContentLength = -1
		}
		s.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := do(strings.NewReader(strings.Repeat("a", 512)), false); code != http.StatusOK {
		t.Fatalf("under the cap: %d", code)
	}
	if code := do(strings.NewReader(strings.Repeat("a", 2048)), false); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Content-Length over the cap: %d, want 413", code)
	}
	if code := do(strings.NewReader(strings.Repeat("a", 2048)), true); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked body over the cap: %d, want 413", code)
	}
}

// multipartUpload is a browser-style file upload of n bytes.
func multipartUpload(n int) (io.Reader, string) {
	var b strings.Builder
	boundary := "----aegis-test-boundary"
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n")
	b.WriteString("Content-Type: application/octet-stream\r\n\r\n")
	b.WriteString(strings.Repeat("a", n))
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return strings.NewReader(b.String()), "multipart/form-data; boundary=" + boundary
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout awaiting response headers" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestUpstreamErrorStatusClassification(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	cases := []struct {
		name string
		r    *http.Request
		err  error
		want int
	}{
		{"connection refused", req, &net.OpError{Op: "dial", Err: errors.New("refused")}, 502},
		{"header timeout", req, timeoutErr{}, 504},
		{"deadline", req, context.DeadlineExceeded, 504},
		{"body cap", req, &http.MaxBytesError{Limit: 10}, 413},
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	cases = append(cases, struct {
		name string
		r    *http.Request
		err  error
		want int
	}{"client gone", req.WithContext(cancelled), context.Canceled, statusClientClosed})
	for _, c := range cases {
		if code, _ := upstreamErrorStatus(c.r, c.err); code != c.want {
			t.Errorf("%s: %d, want %d", c.name, code, c.want)
		}
	}
}

func TestWAFForwardsLargeBodiesInsteadOfRejecting(t *testing.T) {
	var seen atomic.Int64
	sink := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		seen.Store(n)
		w.WriteHeader(http.StatusNoContent)
	})
	h := wrapTestWAF(t, &aegisv1.Host{WafMode: "block"}, sink)
	body, ctype := multipartUpload(3 << 20) // 3 MiB, past the 1 MiB inspection limit
	want := int64(body.(*strings.Reader).Len())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://x/upload", body)
	req.Header.Set("Content-Type", ctype)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("a 3 MiB upload on a Block host got %d; it must be forwarded", rr.Code)
	}
	if seen.Load() != want {
		t.Fatalf("upstream received %d of %d bytes", seen.Load(), want)
	}
	// An attack inside the inspected prefix is still caught.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "http://x/form", strings.NewReader("q=1%27%20UNION%20SELECT%20password%20FROM%20users--"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("SQLi in a small body got %d, want 403", rr.Code)
	}
	// A smaller profile limit is honoured, and still forwards rather than rejects.
	small := wrapTestWAF(t, &aegisv1.Host{WafMode: "block", WafBodyLimitBytes: 16 << 10}, sink)
	body, ctype = multipartUpload(64 << 10)
	want = int64(body.(*strings.Reader).Len())
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "http://x/upload", body)
	req.Header.Set("Content-Type", ctype)
	small.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || seen.Load() != want {
		t.Fatalf("16 KiB limit: status %d, upstream saw %d of %d bytes", rr.Code, seen.Load(), want)
	}
}

// The idle deadline cuts a stalled transfer but not a slow, live one. Uses
// real sockets: deadlines live on the connection.
func TestIdleTimeoutCutsStalledNotSlowResponses(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/drip": // 2.5 s total, a byte every 250 ms: never idle for 1 s
			for i := 0; i < 10; i++ {
				_, _ = w.Write([]byte("x"))
				_ = rc.Flush()
				time.Sleep(250 * time.Millisecond)
			}
		case "/stall": // first byte, then silence for 3 s
			_, _ = w.Write([]byte("x"))
			_ = rc.Flush()
			time.Sleep(3 * time.Second)
			_, _ = w.Write([]byte("y"))
		}
	}))
	t.Cleanup(up.Close)
	h, p := hostPort(t, up)
	s := New()
	s.Apply(&aegisv1.ConfigUpdate{Version: 1, Hosts: []*aegisv1.Host{{
		Id: "idle", DomainNames: []string{"idle.example.com"}, Enabled: true,
		UpstreamScheme: "http", UpstreamHost: h, UpstreamPort: p, IdleTimeoutSeconds: 1,
	}}})
	edge := httptest.NewServer(s)
	t.Cleanup(edge.Close)
	get := func(path string) (string, error) {
		req, _ := http.NewRequest(http.MethodGet, edge.URL+path, nil)
		req.Host = "idle.example.com"
		resp, err := edge.Client().Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	if body, err := get("/drip"); err != nil || body != strings.Repeat("x", 10) {
		t.Fatalf("slow but live response was cut: %q %v", body, err)
	}
	start := time.Now()
	body, err := get("/stall")
	if err == nil && body == "xy" {
		t.Fatal("a response idle for 3 s must be cut by a 1 s idle timeout")
	}
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Fatalf("cut took %s; the deadline is 1 s", d)
	}
}
