package server

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
	"github.com/zypher-systems/aegis/services/proxy/internal/telemetry"
)

func TestMetricsExposeDroppedTelemetry(t *testing.T) {
	em := telemetry.NewEmitter()
	s := NewWithOptions(Options{Telemetry: em})
	for range 5000 { // more than the ring holds
		em.Emit(&aegisv1.TelemetryEvent{})
	}
	if em.Dropped() == 0 {
		t.Fatal("nothing dropped")
	}
	rr := httptest.NewRecorder()
	s.metrics.write(rr, s)
	if want := fmt.Sprintf("aegis_proxy_telemetry_dropped_total %d\n", em.Dropped()); !strings.Contains(rr.Body.String(), want) {
		t.Fatalf("want %q in:\n%s", want, rr.Body)
	}

	rr = httptest.NewRecorder()
	noTelemetry := New()
	noTelemetry.metrics.write(rr, noTelemetry)
	if !strings.Contains(rr.Body.String(), "aegis_proxy_telemetry_dropped_total 0\n") {
		t.Fatalf("a node without telemetry must report zero:\n%s", rr.Body)
	}
}
