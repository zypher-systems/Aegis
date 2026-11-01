package telemetry

import (
	"testing"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestRingDropsOldest(t *testing.T) {
	e := &Emitter{buf: make([]*aegisv1.TelemetryEvent, 3), cap: 3}
	for i := 1; i <= 5; i++ {
		e.Emit(&aegisv1.TelemetryEvent{Status: int32(i)})
	}
	got := e.Drain(10)
	if len(got) != 3 || got[0].Status != 3 || got[2].Status != 5 {
		t.Fatalf("got %#v", got)
	}
	if e.Len() != 0 {
		t.Fatal("expected empty after drain")
	}
}

func TestRequeuePutsUnsentBackInOrder(t *testing.T) {
	e := &Emitter{buf: make([]*aegisv1.TelemetryEvent, 4), cap: 4}
	for i := 1; i <= 3; i++ {
		e.Emit(&aegisv1.TelemetryEvent{Status: int32(i)})
	}
	batch := e.Drain(2)                        // 1, 2 in flight
	e.Emit(&aegisv1.TelemetryEvent{Status: 4}) // queue: 3, 4
	e.Requeue(batch)                           // 1, 2 failed to send
	got := e.Drain(10)
	if len(got) != 4 || got[0].Status != 1 || got[1].Status != 2 || got[2].Status != 3 || got[3].Status != 4 {
		t.Fatalf("got %v", statuses(got))
	}
	// No room: queued (newer) events are kept, the requeue is cut short.
	for i := 5; i <= 8; i++ {
		e.Emit(&aegisv1.TelemetryEvent{Status: int32(i)})
	}
	e.Requeue([]*aegisv1.TelemetryEvent{{Status: 99}})
	if got := e.Drain(10); len(got) != 4 || got[0].Status != 5 {
		t.Fatalf("got %v", statuses(got))
	}
}

func TestDroppedCountsEveryEventLost(t *testing.T) {
	e := &Emitter{buf: make([]*aegisv1.TelemetryEvent, 3), cap: 3}
	for i := 1; i <= 3; i++ {
		e.Emit(&aegisv1.TelemetryEvent{Status: int32(i)})
	}
	if e.Dropped() != 0 {
		t.Fatalf("dropped %d with room left", e.Dropped())
	}
	e.Emit(&aegisv1.TelemetryEvent{Status: 4}) // overwrites the oldest
	e.Emit(&aegisv1.TelemetryEvent{Status: 5})
	if e.Dropped() != 2 {
		t.Fatalf("dropped %d after two overwrites, want 2", e.Dropped())
	}
	batch := e.Drain(2)
	e.Emit(&aegisv1.TelemetryEvent{Status: 6}) // one slot left of the two freed
	e.Requeue(batch)                           // only one of the two fits
	if e.Dropped() != 3 {
		t.Fatalf("dropped %d after a short requeue, want 3", e.Dropped())
	}
	var nilEmitter *Emitter
	if nilEmitter.Dropped() != 0 {
		t.Fatal("nil emitter must report zero")
	}
}

func statuses(evs []*aegisv1.TelemetryEvent) []int32 {
	out := make([]int32, len(evs))
	for i, ev := range evs {
		out[i] = ev.Status
	}
	return out
}
