package telemetry

import (
	"context"
	"encoding/json"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestIngestKeepsRequestDetail(t *testing.T) {
	s := New(Options{})
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{
		TimestampUnixMs: 1000, RequestId: "abc123", Domain: "a.example", Query: "q=1",
		Referer: "https://r/", Protocol: "HTTP/2.0", Scheme: "https", TlsVersion: "TLS 1.3",
		Upstream: "http://10.0.0.5:8080", PeerIp: "10.10.1.2", BytesReceived: 42,
		BlockStage: "waf", BlockDetail: "inbound anomaly score 10 reached the threshold of 5",
		WafMatches: []*aegisv1.WAFMatch{{RuleId: "942100", Message: "SQLi", Severity: 2, Variable: "ARGS", Key: "id", Value: "1 OR 1"}},
	})
	e := s.Live(1)[0]
	if e.ID != "abc123" || e.Query != "q=1" || e.TLSVersion != "TLS 1.3" || e.Upstream != "http://10.0.0.5:8080" ||
		e.PeerIP != "10.10.1.2" || e.BytesReceived != 42 || e.BlockDetail == "" {
		t.Fatalf("event = %+v", e)
	}
	if len(e.WAFMatches) != 1 || e.WAFMatches[0].Key != "id" || e.WAFMatches[0].Severity != 2 {
		t.Fatalf("matches = %+v", e.WAFMatches)
	}
}

func TestIngestGivesOldNodesAnID(t *testing.T) {
	s := New(Options{})
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{TimestampUnixMs: 1})
	if id := s.Live(1)[0].ID; len(id) != 32 {
		t.Fatalf("id = %q", id)
	}
}

func TestRequestLogModes(t *testing.T) {
	served := &aegisv1.TelemetryEvent{TimestampUnixMs: 1, Status: 200}
	blocked := &aegisv1.TelemetryEvent{TimestampUnixMs: 2, Status: 403, BlockStage: "geo"}
	flagged := &aegisv1.TelemetryEvent{TimestampUnixMs: 3, Status: 200, WafAction: "detect"}
	for _, tc := range []struct {
		mode string
		want int
	}{{"", 3}, {"all", 3}, {"security", 2}, {"off", 0}, {"bogus", 3}} {
		s := New(Options{RequestLog: tc.mode})
		for _, ev := range []*aegisv1.TelemetryEvent{served, blocked, flagged} {
			s.Ingest(context.Background(), ev)
		}
		if got := len(s.pendingLog); got != tc.want {
			t.Fatalf("mode %q queued %d, want %d", tc.mode, got, tc.want)
		}
		s.FlushLog(context.Background()) // no store: drains without error
		if len(s.pendingLog) != 0 {
			t.Fatalf("mode %q: queue not drained", tc.mode)
		}
	}
}

func TestRequestLogQueueIsBounded(t *testing.T) {
	s := New(Options{})
	for i := 0; i < logPendingCap+10; i++ {
		s.Ingest(context.Background(), &aegisv1.TelemetryEvent{TimestampUnixMs: 1})
	}
	if len(s.pendingLog) != logPendingCap || s.logDropped.Load() != 10 {
		t.Fatalf("queued %d, dropped %d", len(s.pendingLog), s.logDropped.Load())
	}
}

func TestRetentionDefaultsAndFloor(t *testing.T) {
	s := New(Options{})
	if s.logKeep.Hours() != 7*24 || s.securityKeep.Hours() != 30*24 {
		t.Fatalf("defaults %s / %s", s.logKeep, s.securityKeep)
	}
	s = New(Options{LogRetention: 60 * 24 * 3600e9, SecurityRetention: 24 * 3600e9})
	if s.securityKeep < s.logKeep {
		t.Fatal("blocked requests must be kept at least as long as served ones")
	}
}

func TestSeedLiveKeepsNewerEventsOnTop(t *testing.T) {
	s := New(Options{})
	s.Ingest(context.Background(), &aegisv1.TelemetryEvent{TimestampUnixMs: 300, Path: "/arrived"})
	var raw []json.RawMessage
	for _, p := range []string{"/logged-2", "/logged-1"} { // newest first, as stored
		b, _ := json.Marshal(Event{Path: p})
		raw = append(raw, b)
	}
	s.seedLive(raw)
	live := s.Live(10)
	if len(live) != 3 || live[0].Path != "/arrived" || live[1].Path != "/logged-2" || live[2].Path != "/logged-1" {
		t.Fatalf("live = %+v", live)
	}
	if len(s.pendingLog) != 1 {
		t.Fatal("reloaded events must not be written to the log again")
	}
}
