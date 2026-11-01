package server

import (
	"context"
	"net"
	"sync"
	"time"
)

// ConnTracker knows every client connection accepted through a tracked
// listener, including ones net/http has handed over (WebSockets), which
// http.Server.Shutdown neither waits for nor closes.
type ConnTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// TrackListener wraps ln so accepted connections are tracked until closed.
func (t *ConnTracker) TrackListener(ln net.Listener) net.Listener {
	return &trackedListener{Listener: ln, t: t}
}

func (t *ConnTracker) add(c net.Conn) {
	t.mu.Lock()
	if t.conns == nil {
		t.conns = map[net.Conn]struct{}{}
	}
	t.conns[c] = struct{}{}
	t.mu.Unlock()
}

func (t *ConnTracker) remove(c net.Conn) {
	t.mu.Lock()
	delete(t.conns, c)
	t.mu.Unlock()
}

// Len is the number of open tracked connections.
func (t *ConnTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// Drain waits for every tracked connection to close, or until ctx ends, and
// then closes whatever is left. Returns how many it had to close.
func (t *ConnTracker) Drain(ctx context.Context) int {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for t.Len() > 0 {
		select {
		case <-ctx.Done():
			return t.CloseAll()
		case <-tick.C:
		}
	}
	return 0
}

// CloseAll closes every tracked connection now.
func (t *ConnTracker) CloseAll() int {
	t.mu.Lock()
	conns := make([]net.Conn, 0, len(t.conns))
	for c := range t.conns {
		conns = append(conns, c)
	}
	t.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return len(conns)
}

type trackedListener struct {
	net.Listener
	t *ConnTracker
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, t: l.t}
	l.t.add(tc)
	return tc, nil
}

type trackedConn struct {
	net.Conn
	t    *ConnTracker
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.t.remove(c) })
	return c.Conn.Close()
}

// CloseStreams stops every TCP/UDP stream listener. Sessions already open
// end when the process does.
func (s *Server) CloseStreams() {
	s.streams.Close()
}
