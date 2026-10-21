// Package telemetry buffers access events and pushes them to the control
// plane. Emission never blocks the request path.
package telemetry

import (
	"sync"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

const defaultCap = 4096

// Emitter is a lock-free-enough ring: a short mutex around the buffer, never
// held across I/O.
type Emitter struct {
	mu   sync.Mutex
	buf  []*aegisv1.TelemetryEvent
	head int
	n    int
	cap  int
}

func NewEmitter() *Emitter {
	return &Emitter{buf: make([]*aegisv1.TelemetryEvent, defaultCap), cap: defaultCap}
}

// Emit drops the oldest event when the ring is full.
func (e *Emitter) Emit(ev *aegisv1.TelemetryEvent) {
	if e == nil || ev == nil {
		return
	}
	e.mu.Lock()
	if e.n == e.cap {
		e.head = (e.head + 1) % e.cap
		e.n--
	}
	idx := (e.head + e.n) % e.cap
	e.buf[idx] = ev
	e.n++
	e.mu.Unlock()
}

// Drain removes up to max events.
func (e *Emitter) Drain(max int) []*aegisv1.TelemetryEvent {
	if e == nil || max <= 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.n == 0 {
		return nil
	}
	if max > e.n {
		max = e.n
	}
	out := make([]*aegisv1.TelemetryEvent, 0, max)
	for i := 0; i < max; i++ {
		out = append(out, e.buf[e.head])
		e.buf[e.head] = nil
		e.head = (e.head + 1) % e.cap
		e.n--
	}
	return out
}

// Requeue puts events that could not be sent back at the front, oldest
// first, as far as there is room; newer events already queued win.
func (e *Emitter) Requeue(evs []*aegisv1.TelemetryEvent) {
	if e == nil || len(evs) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(evs) - 1; i >= 0 && e.n < e.cap; i-- {
		e.head = (e.head - 1 + e.cap) % e.cap
		e.buf[e.head] = evs[i]
		e.n++
	}
}

func (e *Emitter) Len() int {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.n
}
