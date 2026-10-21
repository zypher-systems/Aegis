package store

import (
	"strings"
	"testing"
	"time"
)

func TestRequestLogWhereBindsEveryValue(t *testing.T) {
	from := time.Unix(1_800_000_000, 0)
	where, args := requestLogWhere(RequestLogQuery{
		From: from, HostID: "h1", Country: "ru", ClientIP: "203.0.113.5", Stage: "waf",
		Outcome: "flagged", RuleID: "942290", Status: 4, Method: "post", Search: "50%_off'", Path: "/login",
	})
	for _, want := range []string{
		"ts >= $1", "host_id = $2", "country = $3", "client_ip = $4", "block_stage = $5",
		"(block_stage <> '' OR waf_action <> '')", "waf_rule_id = $6", "'rule_id', $6::text",
		"status >= $7", "status < $8", "method = $9", "path = $10", "path ILIKE $12",
	} {
		if !strings.Contains(where, want) {
			t.Fatalf("where %q lacks %q", where, want)
		}
	}
	if strings.Contains(where, "50%") || strings.Contains(where, "'off") {
		t.Fatal("user input must be bound, never inlined")
	}
	if args[2] != "RU" || args[8] != "POST" || args[9] != "/login" || args[11] != `%50\%\_off'%` {
		t.Fatalf("args = %#v", args)
	}
}

func TestRequestLogWhereEmptyMatchesAll(t *testing.T) {
	if where, args := requestLogWhere(RequestLogQuery{}); where != "TRUE" || len(args) != 0 {
		t.Fatalf("%q %v", where, args)
	}
}

func TestRequestCursorRoundTrip(t *testing.T) {
	ts, seq, ok := parseRequestCursor("1800000000123456.42")
	if !ok || seq != 42 || ts.UnixMicro() != 1800000000123456 {
		t.Fatalf("%v %d %v", ts, seq, ok)
	}
	for _, bad := range []string{"", "x.1", "1", "1.y"} {
		if _, _, ok := parseRequestCursor(bad); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
}
