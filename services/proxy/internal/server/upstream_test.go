package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func testPool(rr bool, weights ...int) *upstreamPool {
	p := &upstreamPool{spec: poolSpec{roundRobin: rr}}
	for i, w := range weights {
		a := upstreamAddr{scheme: "http", host: "10.0.0." + strconv.Itoa(i+1), port: 80}
		p.targets = append(p.targets, &liveUpstream{addr: a, weight: w, healthy: true})
	}
	return p
}

func firstHosts(p *upstreamPool, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(strings.TrimPrefix(p.order()[0].host, "10.0.0."))
	}
	return b.String()
}

func TestRoundRobinIsSmoothAndWeighted(t *testing.T) {
	p := testPool(true, 5, 1)
	// nginx's smooth algorithm spreads the light target out instead of
	// sending five in a row to the heavy one.
	if got := firstHosts(p, 12); got != "111211111211" {
		t.Fatalf("5:1 sequence = %s", got)
	}
	p = testPool(true, 1, 1, 1)
	if got := firstHosts(p, 6); got != "123123" {
		t.Fatalf("equal weights = %s", got)
	}
}

func TestRoundRobinSkipsSickAndStillListsThemLast(t *testing.T) {
	p := testPool(true, 1, 1)
	p.markDown(p.targets[0].addr)
	for i := 0; i < 3; i++ {
		o := p.order()
		if o[0].host != "10.0.0.2" || o[1].host != "10.0.0.1" || len(o) != 2 {
			t.Fatalf("order = %v", o)
		}
	}
}

func TestFailoverKeepsConfiguredOrder(t *testing.T) {
	p := testPool(false, 1, 1, 1)
	if got := firstHosts(p, 3); got != "111" {
		t.Fatalf("failover primary = %s", got)
	}
	p.markDown(p.targets[0].addr)
	if o := p.order(); o[0].host != "10.0.0.2" || o[2].host != "10.0.0.1" {
		t.Fatalf("after primary down = %v", o)
	}
}

func TestHTTPProbeUsesPathAndHostAndStatus(t *testing.T) {
	var gotHost, gotPath string
	code := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.Path
		w.WriteHeader(code)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	a := upstreamAddr{scheme: "http", host: u.Hostname(), port: uint32(port)}
	p := &upstreamPool{spec: poolSpec{healthPath: "/healthz", hostHeader: "app.example.com"}}
	p.targets = []*liveUpstream{{addr: a, weight: 1, healthy: true}}

	p.probe()
	if gotPath != "/healthz" || gotHost != "app.example.com" {
		t.Fatalf("probe sent %s %s", gotHost, gotPath)
	}
	if !p.targets[0].healthy {
		t.Fatal("200 must be healthy")
	}
	code = 404
	p.probe()
	if !p.targets[0].healthy {
		t.Fatal("a 404 still means the app answers")
	}
	code = 503
	p.probe()
	p.probe()
	if p.targets[0].healthy || !strings.Contains(p.targets[0].lastErr, "503") {
		t.Fatalf("two 503s must take it down, got healthy=%v err=%q", p.targets[0].healthy, p.targets[0].lastErr)
	}
	code = 200
	p.probe()
	if !p.targets[0].healthy {
		t.Fatal("one good probe brings it back")
	}
}

func TestHostPoolSpec(t *testing.T) {
	h := &aegisv1.Host{
		DomainNames: []string{"app.example.com"}, LbPolicy: "round_robin", HealthPath: "/up",
		Upstreams: []*aegisv1.UpstreamTarget{
			{Scheme: "http", Host: "a", Port: 80, Weight: 3},
			{Scheme: "http", Host: "b", Port: 80},
		},
	}
	spec, ok := hostPoolSpec(h)
	if !ok || !spec.roundRobin || spec.healthPath != "/up" || spec.hostHeader != "app.example.com" {
		t.Fatalf("spec = %+v ok=%v", spec, ok)
	}
	if spec.weights[0] != 3 || spec.weights[1] != 1 {
		t.Fatalf("weights = %v", spec.weights)
	}
	h.UpstreamHostHeader = "upstream"
	spec, _ = hostPoolSpec(h)
	if spec.hostHeader != "" {
		t.Fatalf("upstream mode must probe with the target's own host, got %q", spec.hostHeader)
	}
	other, _ := hostPoolSpec(h)
	if !spec.equal(other) {
		t.Fatal("identical specs must compare equal")
	}
	h.Upstreams[0].Weight = 4
	other, _ = hostPoolSpec(h)
	if spec.equal(other) {
		t.Fatal("a weight change must rebuild the pool")
	}
}
