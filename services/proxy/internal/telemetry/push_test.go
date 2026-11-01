package telemetry

import (
	"context"
	"errors"
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

type fakeStream struct {
	sent   []*aegisv1.TelemetryEvent
	failAt int // fail on this send (1-based); 0 never
	onSend func()
}

func (f *fakeStream) Send(ev *aegisv1.TelemetryEvent) error {
	if f.failAt > 0 && len(f.sent)+1 == f.failAt {
		return errors.New("stream gone")
	}
	f.sent = append(f.sent, ev)
	if f.onSend != nil {
		f.onSend()
	}
	return nil
}

func fill(e *Emitter, n int) {
	for i := 1; i <= n; i++ {
		e.Emit(&aegisv1.TelemetryEvent{Status: int32(i)})
	}
}

// One tick must clear the ring, however full, or sustained traffic above
// what a tick sends fills the ring and drops events.
func TestSendQueuedEmptiesTheRing(t *testing.T) {
	e := NewEmitter()
	fill(e, defaultCap)
	f := &fakeStream{}
	if err := sendQueued(context.Background(), f, e); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != defaultCap || e.Len() != 0 {
		t.Fatalf("sent %d, left %d", len(f.sent), e.Len())
	}
	if f.sent[0].Status != 1 || f.sent[defaultCap-1].Status != defaultCap {
		t.Fatal("events out of order")
	}
	if e.Dropped() != 0 {
		t.Fatalf("dropped %d", e.Dropped())
	}
}

func TestSendQueuedPutsUnsentBack(t *testing.T) {
	e := NewEmitter()
	fill(e, 10)
	f := &fakeStream{failAt: 4}
	if err := sendQueued(context.Background(), f, e); err == nil {
		t.Fatal("send error not returned")
	}
	if len(f.sent) != 3 || e.Len() != 7 {
		t.Fatalf("sent %d, left %d", len(f.sent), e.Len())
	}
	if got := e.Drain(1); got[0].Status != 4 {
		t.Fatalf("resumes at %d, want 4", got[0].Status)
	}
}

// Shutdown hands over to the final flush instead of racing it for events.
func TestSendQueuedStopsOnShutdown(t *testing.T) {
	e := NewEmitter()
	fill(e, 3*pushBatch)
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeStream{}
	f.onSend = func() {
		if len(f.sent) == pushBatch {
			cancel()
		}
	}
	if err := sendQueued(ctx, f, e); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != pushBatch || e.Len() != 2*pushBatch {
		t.Fatalf("sent %d, left %d", len(f.sent), e.Len())
	}
}
