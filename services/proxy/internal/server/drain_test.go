package server

import (
	"context"
	"net"
	"testing"
	"time"

	aegisv1 "github.com/zypher-systems/aegis/gen/aegis/v1"
)

func TestConnTrackerDrainWaitsThenForcesClose(t *testing.T) {
	var tr ConnTracker
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tr.TrackListener(ln)
	defer tl.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1, c2 := dial(), dial()
	s1, s2 := <-accepted, <-accepted
	if tr.Len() != 2 {
		t.Fatalf("tracking %d, want 2", tr.Len())
	}
	// A connection that finishes on its own is waited for, not closed.
	go func() {
		time.Sleep(200 * time.Millisecond)
		s1.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	go func() {
		time.Sleep(600 * time.Millisecond)
		s2.Close() // the "WebSocket" ends before the budget runs out
	}()
	if forced := tr.Drain(ctx); forced != 0 {
		t.Fatalf("forced %d closes; both ended on their own", forced)
	}
	if d := time.Since(start); d < 500*time.Millisecond || d > 1500*time.Millisecond {
		t.Fatalf("drain took %s; should return once the last connection closes", d)
	}
	c1.Close()
	c2.Close()

	// Past the budget, what is left is closed.
	c3 := dial()
	s3 := <-accepted
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	if forced := tr.Drain(ctx2); forced != 1 {
		t.Fatalf("forced %d, want 1", forced)
	}
	buf := make([]byte, 1)
	s3.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := s3.Read(buf); err == nil {
		t.Fatal("server side should be closed")
	}
	c3.Close()
	if tr.Len() != 0 {
		t.Fatalf("still tracking %d", tr.Len())
	}
}

func TestStreamManagerCloseStopsListeningAndStaysClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	m := newStreamManager()
	host := &aegisv1.Host{
		Id: "st", Kind: aegisv1.HostKind_HOST_KIND_STREAM, ListenProtocol: aegisv1.ListenProtocol_LISTEN_PROTOCOL_TCP,
		ListenPort: port, UpstreamScheme: "tcp", UpstreamHost: "127.0.0.1", UpstreamPort: 9,
	}
	m.Sync([]*aegisv1.Host{host})
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream listener never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	m.Close()
	time.Sleep(100 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("listener still accepting after Close")
	}
	// A late Sync (config push racing the shutdown) must not reopen it.
	m.Sync([]*aegisv1.Host{host})
	time.Sleep(100 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("Sync after Close reopened the listener")
	}
}
