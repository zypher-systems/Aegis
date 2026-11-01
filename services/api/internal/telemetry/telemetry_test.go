package telemetry

import (
	"context"
	"testing"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestIngestLiveAndSummary(t *testing.T) {
	s := New(Options{})
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{
		Path: "/", Status: 200, DurationMs: 0.4, ClientIp: "1.2.3.4", NodeId: "n1", Country: "US",
	})
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{
		Path: "/api", Status: 404, DurationMs: 12, ClientIp: "1.2.3.4", NodeId: "n1", Country: "US",
	})
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{
		Path: "/", Status: 200, DurationMs: 0.8, ClientIp: "8.8.8.8", NodeId: "n2", Country: "DE",
		WafAction: "block", WafRuleId: "942100", WafScore: 5,
	})
	if s.Received() != 3 {
		t.Fatalf("received=%d", s.Received())
	}
	live := s.Live(10)
	if len(live) != 3 || live[0].Path != "/" {
		t.Fatalf("live=%+v", live)
	}
	if live[0].WAFAction != "block" || live[0].WAFRuleID != "942100" || live[0].WAFScore != 5 {
		t.Fatalf("waf fields=%+v", live[0])
	}
	sum := s.Summary()
	if sum.WindowEvents != 3 || sum.P50Ms <= 0 {
		t.Fatalf("summary=%+v", sum)
	}
	if len(sum.TopPaths) == 0 || sum.TopPaths[0].Key != "/" {
		t.Fatalf("top paths=%+v", sum.TopPaths)
	}
	if len(sum.Geo) != 2 {
		t.Fatalf("geo=%+v", sum.Geo)
	}
	stats := s.NodeStats()
	if stats["n1"].Requests != 2 {
		t.Fatalf("node stats=%+v", stats)
	}
}

func TestEmptySummaryJSONHasArrays(t *testing.T) {
	s := New(Options{})
	sum := s.Summary()
	if sum.Histogram == nil || sum.Geo == nil || sum.TopPaths == nil || sum.BlockedByStage == nil {
		t.Fatalf("nil slices in empty summary: %+v", sum)
	}
}

func TestPercentile(t *testing.T) {
	if v := percentile([]float64{1, 2, 3, 4, 5}, 0.50); v != 3 {
		t.Fatalf("p50=%v", v)
	}
	if v := percentile(nil, 0.99); v != 0 {
		t.Fatalf("empty=%v", v)
	}
}

func TestRollupKeyCollapsesPathCountryNode(t *testing.T) {
	s := New(Options{})
	ts := time.Date(2026, 9, 8, 12, 3, 0, 0, time.UTC).UnixMilli()
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{
		TimestampUnixMs: ts, HostId: "h1", Domain: "ex.com", Path: "/a",
		Status: 200, NodeId: "n1", Country: "US", DurationMs: 1, BytesSent: 10,
	})
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{
		TimestampUnixMs: ts, HostId: "h1", Domain: "ex.com", Path: "/b",
		Status: 201, NodeId: "n2", Country: "DE", DurationMs: 2, BytesSent: 20,
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) != 1 {
		t.Fatalf("pending keys=%d want 1", len(s.pending))
	}
	if len(s.pendingGeo) != 2 {
		t.Fatalf("geo keys=%d want 2 (US, DE)", len(s.pendingGeo))
	}
	for k, acc := range s.pending {
		if acc.count != 2 || acc.bytes != 30 {
			t.Fatalf("acc=%+v", acc)
		}
		if k.host != "h1" || k.domain != "ex.com" || k.statusClass != 2 || k.blockStage != "" {
			t.Fatalf("key=%+v", k)
		}
	}
}

func TestBlockStageSummaryAndRollupGrain(t *testing.T) {
	s := New(Options{})
	ts := time.Date(2026, 9, 8, 12, 3, 0, 0, time.UTC).UnixMilli()
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{
		TimestampUnixMs: ts, Path: "/", Status: 200, DurationMs: 1,
	})
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{
		TimestampUnixMs: ts, Path: "/", Status: 403, DurationMs: 1,
		BlockStage: "crowdsec", CrowdsecOrigin: "CAPI",
	})
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{
		TimestampUnixMs: ts, Path: "/", Status: 403, DurationMs: 1,
		BlockStage: "waf",
	})
	sum := s.Summary()
	if sum.Blocked != 2 || len(sum.BlockedByStage) != 2 {
		t.Fatalf("summary=%+v", sum)
	}
	live := s.Live(1)
	if live[0].CrowdSecOrigin != "CAPI" && live[0].BlockStage != "waf" {
		t.Fatalf("live=%+v", live[0])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) != 3 {
		t.Fatalf("pending keys=%d want 3", len(s.pending))
	}
}
